"""
AegisPilot ML - code features (version 3): counts computed from a package archive's bytes. The code is read as text
and parsed, never run, and nothing is written to disk.

Version 2 fixed false alarms found by reviewing alerts on 300 new packages:
  1. the exec pattern counted method calls such as re.compile( - a call preceded by "." or a word character is skipped
  2. the credential-theft pattern ignored case and matched "local state" in comments or "PasskeyLogin" in names -
     'Login Data' / 'Local State' now match case-sensitively inside quotes only, keylog only at a word start
  3. comments and docstrings were counted - they are removed first (data hidden in string variables is still read)
  4. "requests." matched variable names (self.requests) and prose - only real calls and imports count

Version 3 adds when code runs (benign tools also run commands and decode data; running it at install or import is
the signal):
  auto_process      external commands run at import or install time
  auto_network      network access at import or install time
  auto_exec         exec / eval at import or install time
  decode_exec_chain decoded data passed straight to exec / eval (exec(b64decode(...)))
  "At import or install time": not inside a function or lambda; module level and class bodies count, all of setup.py
  counts, the body of `if __name__ == "__main__":` does not. Function definitions named compile( are not exec calls.
"""
import io
import re
import tarfile
import zipfile
import ast
import tokenize
import pyzipper

VERSION = 3
MAX_MEMBER = 5 * 1024 * 1024    # largest single file read (compression bombs)
MAX_TOTAL = 60 * 1024 * 1024    # total read from one package
MAX_DEPTH = 2                   # archives inside archives: two levels
TOKENIZE_LIMIT = 500_000        # larger files: only comment lines are removed (speed)
MAX_INFLATED = 512 * 1024 * 1024   # one compressed stream (tar.gz/bz2/xz) inflates to at most this (a 20MB bomb inflated to 20GB)
MAX_INFLATED_TOTAL = 1024 * 1024 * 1024   # all streams, nested ones included
MAX_RATIO = 150                    # inflated / compressed size: real sdists reach about 24, bombs about 1000


class ArchiveLimitError(Exception):
    """An archive limit was reached: the code is not read, the metadata model is used and code_source says why."""


ARCHIVE_EXT = (".zip", ".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar")

PAT = {
    # the builtins exec / eval / compile only: not method calls (re.compile(, self.eval() nor definitions (def compile()
    "exec": re.compile(r"(?<![\w.])(?<!def )(?:exec|eval|compile)\s*\("),
    "decode": re.compile(r"b64decode|b32decode|a85decode|zlib\.decompress|marshal\.loads|"
                         r"codecs\.decode|bytes\.fromhex"),
    "process": re.compile(r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b|\bPopen\s*\(|\bpty\.spawn\b"),
    # requests: real calls (requests.get( ...) and imports only
    "network": re.compile(r"\burllib\b|(?<![\w.])requests\.(?:get|post|put|delete|patch|head|request|Session)\b"
                          r"|^\s*(?:import|from)\s+requests\b|\bsocket\.|\bhttp\.client\b|\burlopen\b"
                          r"|\bhttpx\b|\baiohttp\b", re.M),
    # addresses ignore case; browser file names match case-sensitively inside quotes only
    "sensitive": re.compile(r"(?i:discord(?:app)?\.com/api/webhooks|api\.telegram\.org|pastebin\.com"
                            r"|\bngrok\b|\bkeylog)|\.ssh/"
                            r"|['\"][^'\"\n]*(?:Login Data|Local State)[^'\"\n]*['\"]"),
}
LONG_BLOB = re.compile(r"[A-Za-z0-9+/=_\-]{200,}")

CODE_FEATURES = ["n_py", "code_lines", "max_line_len", "obfuscation_rate",
                 "exec_cnt", "decode_cnt", "long_blob_cnt", "process_cnt", "network_cnt",
                 "sensitive_cnt", "setup_exec", "setup_decode", "setup_process",
                 "setup_network", "setup_sensitive", "install_hook",
                 # version 3
                 "auto_process", "auto_network", "auto_exec", "decode_exec_chain"]
AUTO_FEATURES = ["auto_process", "auto_network", "auto_exec", "decode_exec_chain"]

_DOC_PREV = {tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT, tokenize.ENCODING}
_COMMENT_LINE = re.compile(r"(?m)^[ \t]*#.*$")


def strip_comments_docstrings(text):
    """Comments and docstrings replaced by spaces; line numbers and line count stay the same."""
    if len(text) > TOKENIZE_LIMIT:
        return _COMMENT_LINE.sub("", text)
    try:
        spans = []                      # [(start, end)] to blank
        prev = tokenize.NEWLINE
        pending = None                  # a docstring candidate (decided by the next token)
        for t in tokenize.generate_tokens(io.StringIO(text).readline):
            if pending is not None:
                if t.type in (tokenize.NEWLINE, tokenize.ENDMARKER, tokenize.COMMENT):
                    spans.append(pending)          # a statement that is one string = a docstring
                pending = None
            if t.type == tokenize.COMMENT:
                spans.append((t.start, t.end))
            elif t.type == tokenize.STRING and prev in _DOC_PREV:
                pending = (t.start, t.end)
            if t.type not in (tokenize.NL, tokenize.COMMENT):
                prev = t.type
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return _COMMENT_LINE.sub("", text)
    if not spans:
        return text
    lines = text.splitlines(keepends=True)
    for (sr, sc), (er, ec) in spans:
        for r in range(sr, min(er, len(lines)) + 1):
            line = lines[r - 1]
            body = line.rstrip("\r\n")
            nl = line[len(body):]
            a = sc if r == sr else 0
            b = min(ec if r == er else len(body), len(body))
            if a < b:
                lines[r - 1] = body[:a] + " " * (b - a) + body[b:] + nl
    return "".join(lines)


# ---------------- version 3: what runs at import or install time (AST) ----------------
_DECODE_TAIL = ("b64decode", "b32decode", "a85decode", "b85decode", "fromhex")
_DECODE_FULL = ("zlib.decompress", "marshal.loads", "codecs.decode", "gzip.decompress", "bz2.decompress",
                "lzma.decompress")


def _dotted(func):
    """The called name: subprocess.run, os.system, exec, base64.b64decode ..."""
    parts = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _kind(name):
    if not name:
        return None
    last = name.split(".")[-1]
    if name in ("exec", "eval", "compile", "builtins.exec", "builtins.eval"):
        return "exec"
    if name.startswith("subprocess.") or last in ("Popen",) or name in ("os.system", "os.popen", "pty.spawn",
                                                                          "os.execv", "os.execl", "os.spawnl"):
        return "process"
    if (name.startswith(("urllib.", "socket.", "http.client.", "httpx.", "aiohttp."))
            or last == "urlopen"
            or (name.startswith("requests.") and last in ("get", "post", "put", "delete", "patch", "head",
                                                         "request", "Session"))):
        return "network"
    if last in _DECODE_TAIL or name in _DECODE_FULL:
        return "decode"
    return None


def _is_main_guard(node):
    t = node.test
    return (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__"
            and any(isinstance(c, ast.Constant) and c.value == "__main__" for c in t.comparators))


class _AutoVisitor(ast.NodeVisitor):
    def __init__(self, is_setup):
        self.is_setup = is_setup
        self.depth = 0                     # function nesting (0 = runs at import)
        self.c = {k: 0 for k in AUTO_FEATURES}

    def _in_func(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    visit_FunctionDef = visit_AsyncFunctionDef = visit_Lambda = _in_func

    def visit_If(self, node):
        if _is_main_guard(node):           # the body of if __name__ == "__main__": does not run at import
            self.visit(node.test)
            self.depth += 1
            for n in node.body:
                self.visit(n)
            self.depth -= 1
            for n in node.orelse:
                self.visit(n)
        else:
            self.generic_visit(node)

    def visit_Call(self, node):
        kind = _kind(_dotted(node.func))
        auto = self.is_setup or self.depth == 0
        if auto and kind in ("process", "network", "exec"):
            self.c[f"auto_{kind}"] += 1
        if kind == "exec":                 # decoded data run right away? (anywhere)
            for arg in node.args:
                if any(isinstance(n, ast.Call) and _kind(_dotted(n.func)) == "decode" for n in ast.walk(arg)):
                    self.c["decode_exec_chain"] += 1
                    break
        self.generic_visit(node)


_CHAIN_RE = re.compile(r"(?<![\w.])(?:exec|eval)\s*\([^\n]*?(?:b64decode|b32decode|b85decode|fromhex"
                       r"|zlib\.decompress|marshal\.loads|codecs\.decode)")


def auto_features(code, is_setup):
    """Counts of risky calls that run at import or install time. Code that does not parse: unindented lines instead."""
    if len(code) <= TOKENIZE_LIMIT:
        try:
            v = _AutoVisitor(is_setup)
            v.visit(ast.parse(code))
            return v.c
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            pass
    c = {k: 0 for k in AUTO_FEATURES}
    for line in code.splitlines():
        top = is_setup or (line[:1] not in (" ", "\t") and line.strip())
        if top:
            c["auto_process"] += len(PAT["process"].findall(line))
            c["auto_network"] += len(PAT["network"].findall(line))
            c["auto_exec"] += len(PAT["exec"].findall(line))
    c["decode_exec_chain"] = len(_CHAIN_RE.findall(code))
    return c



def _check_inflation(data, budget):
    """How far a gz/bz2/xz stream inflates, counted up to a limit and thrown away (nothing on disk); ArchiveLimitError
    past it. tarfile inflates the whole stream to list the members, so this runs before tarfile opens it. At most 1MB is
    inflated at a time, which bounds memory too."""
    import bz2
    import lzma
    import zlib
    if data[:2] == b"\x1f\x8b":
        make = lambda: zlib.decompressobj(31)
    elif data[:3] == b"BZh":
        make = bz2.BZ2Decompressor
    elif data[:6] == b"\xfd7zXZ\x00":
        make = lzma.LZMADecompressor
    else:
        return
    step = 1 << 20

    def pieces(d, chunk):
        yield d.decompress(chunk, step)
        if hasattr(d, "unconsumed_tail"):                      # zlib
            while d.unconsumed_tail and not d.eof:             # after the end of a member the tail is unused_data, not input
                out = d.decompress(d.unconsumed_tail, step)
                if not out and not d.eof:                      # no progress: never loop forever on odd input
                    break
                yield out
        else:                                                   # bz2 / lzma keep the rest of the input internally
            while not d.eof and not d.needs_input:
                yield d.decompress(b"", step)

    d, inflated, pos, chunk = make(), 0, 0, b""
    try:
        while pos < len(data) or chunk:
            if not chunk:
                chunk, pos = data[pos:pos + 65536], pos + 65536
            for out in pieces(d, chunk):
                inflated += len(out); budget[1] += len(out)
                if inflated > MAX_INFLATED or budget[1] > MAX_INFLATED_TOTAL:
                    raise ArchiveLimitError(f"inflates to more than {inflated >> 20}MB (limit {MAX_INFLATED >> 20}MB)")
                if inflated >= 64 * 1024 * 1024 and inflated > MAX_RATIO * max(pos, 1):
                    raise ArchiveLimitError(f"compression ratio {inflated // max(pos, 1)} (limit {MAX_RATIO})")
            chunk = b""
            if d.eof:                                           # next member of a multi-member stream
                chunk, d = d.unused_data, make()
    except ArchiveLimitError:
        raise
    except Exception:
        return                                                  # not a readable stream: tarfile will report it itself


def _iter_py(data, depth, budget):
    """(path, code text) for each Python file in the archive bytes. Nothing is written to disk."""
    bio = io.BytesIO(data)
    members = []
    if zipfile.is_zipfile(bio):
        z = pyzipper.AESZipFile(bio)
        z.setpassword(b"infected")              # the password malware sample archives use (training data)
        for info in z.infolist():
            if not info.is_dir() and info.file_size <= MAX_MEMBER:
                members.append((info.filename, lambda i=info: z.read(i)))
    else:
        bio.seek(0)
        _check_inflation(data, budget)
        try:
            t = tarfile.open(fileobj=bio, mode="r:*")
        except tarfile.TarError:
            return
        for m in t.getmembers():
            if m.isfile() and m.size <= MAX_MEMBER:
                members.append((m.name, lambda m=m: t.extractfile(m).read()))

    for name, read in members:
        low = name.lower()
        is_py = low.endswith(".py")
        is_arc = low.endswith(ARCHIVE_EXT) and depth < MAX_DEPTH
        if not (is_py or is_arc) or budget[0] > MAX_TOTAL:
            continue
        content = read()
        budget[0] += len(content)
        if is_py:
            yield name, content.decode("utf-8", "ignore")
        else:
            yield from _iter_py(content, depth + 1, budget)


def code_features(data, debug=False):
    f = {k: 0 for k in CODE_FEATURES}
    for name, text in _iter_py(data, 0, [0, 0]):
        if debug:
            print("   read:", name)
        code = strip_comments_docstrings(text)            # the code without comments and docstrings
        f["n_py"] += 1
        f["code_lines"] += len(text.splitlines())
        f["max_line_len"] = max(f["max_line_len"],
                                max((len(l.rstrip()) for l in code.splitlines()), default=0))
        counts = {k: len(p.findall(code)) for k, p in PAT.items()}
        f["exec_cnt"] += counts["exec"]
        f["decode_cnt"] += counts["decode"]
        f["process_cnt"] += counts["process"]
        f["network_cnt"] += counts["network"]
        f["sensitive_cnt"] += counts["sensitive"]
        f["long_blob_cnt"] += len(LONG_BLOB.findall(code))
        is_setup = name.replace("\\", "/").split("/")[-1] == "setup.py"
        for k, v in auto_features(code, is_setup).items():
            f[k] += v
        if is_setup:
            for k in ["exec", "decode", "process", "network", "sensitive"]:
                f[f"setup_{k}"] = max(f[f"setup_{k}"], int(counts[k] > 0))
            f["install_hook"] = max(f["install_hook"], int("cmdclass" in code))
    hits = f["exec_cnt"] + f["decode_cnt"] + f["long_blob_cnt"]
    f["obfuscation_rate"] = hits / max(f["code_lines"], 1) * 1000
    return f
