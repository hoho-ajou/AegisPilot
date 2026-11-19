"""
AegisPilot ML - code features of an npm package (JavaScript), the npm counterpart of code_features.py. The code is read
as text, never run, and nothing is written to disk.

The counts mean what their PyPI namesakes mean, with JavaScript's ways of doing it:
  exec       eval(, Function( / new Function(, vm.runIn*Context / vm.Script / vm.compileFunction
  decode     Buffer.from(..., 'base64'|'hex'), atob(, zlib inflate/gunzip/unzip/brotliDecompress, String.fromCharCode(
  process    child_process (require/import) and, in a file that uses it, exec/execSync/spawn/spawnSync/execFile/fork calls
  network    http/https/net/tls/dns/dgram modules (require/import, node-fetch, axios) and network calls: http.get(,
             https.request(, net.connect(, dns.lookup(, fetch(, axios.get(, new XMLHttpRequest, new WebSocket(
  sensitive  webhooks, Telegram bots, pastebin, ngrok, ~/.ssh, ~/.npmrc, ~/.aws/credentials, browser profile files,
             crypto-wallet names, the whole environment serialised (JSON.stringify(process.env))
  recon      os.hostname / os.userInfo / os.networkInterfaces / os.homedir (machine fingerprinting, typical of
             dependency-confusion probes) - npm only
  obf_ident  identifiers of javascript-obfuscator (_0x1a2b) - npm only

When code runs: npm runs a package's code at install through its lifecycle scripts (preinstall / install / postinstall)
and at `require` through the top level of its files. So
  install_*  the files the lifecycle scripts run (and `node -e` code in them): any signal there runs at install
             (the setup_* features of PyPI: setup.py)
  auto_*     process / network / exec CALLS at the top level of any file (a top-level `require('https')` alone is not
             one: nearly every HTTP library has it): not inside a function body, except functions that are called right
             where they are defined (IIFE: (function(){...})(), !function(){...}(), (() => {...})())
Comments are removed first (strings stay: data hidden in strings is still read). A file over STRUCT_LIMIT characters is
counted, but not split into top level and functions (minified bundles): its auto_* stay 0.

Time limit: the guard gives the model 45 seconds and npm packages ship tens of MB of bundled JavaScript (a CLI measured
58MB in 760 files). The files the install scripts run are always counted in full; the others in a fixed order, the
smallest first, until ANALYZE_BUDGET characters are counted; the rest add only to n_js, code_lines and max_line_len.
Training and the guard use the same order and budget, so they give the same numbers.
"""
import bisect
import io
import posixpath
import re
import tarfile
import zipfile

from code_features import (MAX_MEMBER, MAX_TOTAL, MAX_DEPTH, AES_COMPRESS_TYPE, ArchiveLimitError,  # noqa: F401
                           UnreadableArchive, _check_inflation)

VERSION = 2
STRUCT_LIMIT = 200_000          # larger files: no top-level analysis (speed; such files are minified bundles)
ANALYZE_BUDGET = 8_000_000      # characters of JavaScript counted in full per package (see the module docstring)
JS_SUFFIXES = (".js", ".mjs", ".cjs")
# The files the guard keeps from an npm tarball (sources/npm.KEEP_SUFFIXES): the size and file-count features are counted
# over these only, so a tarball read here and one the guard unpacked give the same numbers.
KEEP_SUFFIXES = (".js", ".mjs", ".cjs", ".json", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".py", ".md", ".gyp", ".gypi",
                 ".mk", "/makefile", "/gnumakefile")
ARCHIVE_EXT = (".zip", ".tgz", ".tar.gz", ".tar")

PAT = {
    "exec": re.compile(r"(?<![\w.$])(?:eval|Function)\s*\(|\bvm\.(?:runIn(?:New|This)?Context|Script|compileFunction)\b"),
    "decode": re.compile(r"Buffer\.from\s*\([^)\n]{0,4000}?['\"](?:base64|hex|base64url)['\"]|(?<![\w.$])atob\s*\("
                         r"|\bzlib\.(?:inflate|inflateRaw|gunzip|unzip|brotliDecompress)(?:Sync)?\b"
                         r"|String\.fromCharCode\s*\("),
    "process_mod": re.compile(r"child_process"),
    # bare names (destructured imports) and methods; `.exec(` only on child_process itself or a name for it (cp,
    # childProcess, ...Process) - RegExp#exec is not a command
    "process_call": re.compile(r"(?<![\w$.])(?:execSync|spawnSync|execFileSync|execFile|spawn|fork|exec)\s*\("
                               r"|\.(?:execSync|spawnSync|execFileSync|execFile|spawn|fork)\s*\("
                               r"|(?:\b(?:cp|child|childProcess|child_process|\w*[Pp]rocess\w*)|\))\s*\.exec\s*\("),
    "network_mod": re.compile(r"""require\s*\(\s*['"](?:node:)?(?:https?|net|tls|dns|dgram|http2|node-fetch|axios)"""
                              r"""['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|tls|dns|dgram|http2|node-fetch|axios)['"]"""),
    "network_call": re.compile(r"\b(?:https?|net|tls|dns|dgram|http2)\.(?:request|get|connect|createConnection"
                               r"|createSocket|lookup|resolve\w*)\s*\("
                               r"|(?<![\w.$])fetch\s*\(|\baxios(?:\.(?:get|post|put|request))?\s*\("
                               r"|\bnew\s+(?:XMLHttpRequest|WebSocket)\b"),
    "sensitive": re.compile(r"(?i:discord(?:app)?\.com/api/webhooks|api\.telegram\.org|pastebin\.com|\bngrok\b"
                            r"|\bkeylog|metamask|wallet\.dat|\bexodus\b|\belectrum\b)"
                            r"|\.ssh/|\.npmrc|\.aws/credentials|['\"][^'\"\n]*(?:Login Data|Local State)[^'\"\n]*['\"]"
                            r"|JSON\.stringify\s*\(\s*process\.env\s*\)"),
    "recon": re.compile(r"\bos\.(?:hostname|userInfo|networkInterfaces|homedir)\s*\("),
    "obf_ident": re.compile(r"\b_0x[0-9a-f]{4,6}\b"),
}
LONG_BLOB = re.compile(r"[A-Za-z0-9+/=_\-]{200,}")
CHAIN = re.compile(r"(?<![\w.$])(?:eval|Function)\s*\([^\n]{0,4000}?(?:Buffer\.from|atob\s*\(|fromCharCode"
                   r"|zlib\.(?:inflate|gunzip|unzip))")

JS_CODE_FEATURES = ["n_js", "code_lines", "max_line_len", "minified_files", "obfuscation_rate",
                    "exec_cnt", "decode_cnt", "long_blob_cnt", "obf_ident_cnt",
                    "process_cnt", "network_cnt", "sensitive_cnt", "recon_cnt",
                    "install_exec", "install_decode", "install_process", "install_network", "install_sensitive",
                    "auto_process", "auto_network", "auto_exec", "decode_exec_chain"]
_CTRL = {"if", "for", "while", "switch", "catch", "with"}
_REGEX_PREV = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_WORDS = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await"}


# ------------------------------------------------------------------------------------------------- a small JS lexer

def _scan(text, want_structure=True):
    """(code with comments blanked, [(start, end)] function bodies that do not run when the file is loaded).
    Strings, template literals and regular expressions are skipped (their braces are not code); comments become spaces
    so line numbers and lengths stay. Approximate, and never fails: anything odd is read as code."""
    out = list(text)
    n = len(text)
    i = 0
    bodies = []                     # finished function bodies (start, end) that are not called in place
    braces = []                     # stack: (is_function, start)
    parens = []                     # stack: kind of the word before "(": "ctrl" / "func" / "call"
    last_paren = None               # kind of the last closed "("
    last_sig = ""                   # last significant character ("" at the start)
    word, prev_word = "", ""
    arrow = False                   # the last token was =>

    def blank(a, b):
        for k in range(a, b):
            if out[k] not in "\r\n":
                out[k] = " "

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":                     # line comment
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
            continue
        if c == "/" and nxt == "*":                     # block comment
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank(i, j)
            i = j
            continue
        if c in "'\"":                                  # string: to the same quote on the same line
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            i, last_sig, word, arrow = j + 1, c, "", False
            continue
        if c == "`":                                    # template literal (its ${...} is read as part of the string)
            j = i + 1
            while j < n and text[j] != "`":
                j += 2 if text[j] == "\\" else 1
            i, last_sig, word, arrow = j + 1, c, "", False
            continue
        if c == "/" and (last_sig == "" or last_sig in _REGEX_PREV or word in _REGEX_WORDS):   # regular expression
            j, in_class = i + 1, False
            while j < n and text[j] != "\n":
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    break
                j += 1
            i, last_sig, word, arrow = j + 1, "/", "", False
            continue
        if c.isalnum() or c in "_$":
            j = i
            while j < n and (text[j].isalnum() or text[j] in "_$"):
                j += 1
            prev_word, word = word if word else prev_word, text[i:j]
            i, last_sig, arrow = j, "w", False
            continue
        if c.isspace():
            i += 1
            continue
        if want_structure:
            if c == "(":
                if word in _CTRL:
                    kind = "ctrl"
                elif word == "function" or prev_word == "function":
                    kind = "func"
                else:
                    kind = "call"
                parens.append(kind)
            elif c == ")":
                last_paren = parens.pop() if parens else None
            elif c == "{":
                is_fn = arrow or (last_sig == ")" and last_paren in ("func", "call"))
                braces.append((is_fn, i))
            elif c == "}":
                if braces:
                    is_fn, start = braces.pop()
                    if is_fn and not _called_in_place(text, i + 1):
                        bodies.append((start, i + 1))
        arrow = c == ">" and i > 0 and text[i - 1] == "="
        prev_word = word if word else prev_word
        word = ""
        last_sig = c
        i += 1
    return "".join(out), _merge(bodies)


_IIFE_TAIL = re.compile(r"\s*(?:\)\s*)?(?:\(|\.(?:call|apply)\s*\()")


def _called_in_place(text, j):
    """The function that ends at j is called right there: `})(`, `}(`, `}).call(`."""
    return bool(_IIFE_TAIL.match(text, j))


def _merge(spans):
    spans.sort()
    merged = []
    for a, b in spans:
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def _inside(spans, starts, pos):
    k = bisect.bisect_right(starts, pos) - 1
    return k >= 0 and pos < spans[k][1]


def _process_hits(code):
    """(module mentions, call positions): calls count only in a file that uses child_process."""
    mods = len(PAT["process_mod"].findall(code))
    if not mods:
        return 0, []
    return mods, [m.start() for m in PAT["process_call"].finditer(code)]


def size_counts(text):
    """The counts every file gets, even past the budget: one file, its lines, its longest line."""
    lines = text.split("\n")
    return {"n_js": 1, "code_lines": len(lines) - (1 if lines and lines[-1] == "" else 0),
            "max_line_len": max((len(l.rstrip()) for l in lines), default=0)}


def file_counts(text, install_time=False):
    """The counts of one JavaScript file. install_time: an install script runs this file."""
    big = len(text) > STRUCT_LIMIT
    code, bodies = _scan(text, want_structure=not big)
    starts = [a for a, _ in bodies]
    c = {k: 0 for k in JS_CODE_FEATURES}
    c.update(size_counts(text))
    c["max_line_len"] = max((len(l.rstrip()) for l in code.split("\n")), default=0)   # comments do not count
    c["minified_files"] = int(c["max_line_len"] > 1000 and c["code_lines"] < 50)
    exec_pos = [m.start() for m in PAT["exec"].finditer(code)]
    c["exec_cnt"] = len(exec_pos)
    c["decode_cnt"] = len(PAT["decode"].findall(code))
    c["long_blob_cnt"] = len(LONG_BLOB.findall(code))
    c["obf_ident_cnt"] = len(PAT["obf_ident"].findall(code))
    proc_mods, proc_pos = _process_hits(code)
    c["process_cnt"] = proc_mods + len(proc_pos)
    net_pos = [m.start() for m in PAT["network_call"].finditer(code)]
    c["network_cnt"] = len(PAT["network_mod"].findall(code)) + len(net_pos)
    c["sensitive_cnt"] = len(PAT["sensitive"].findall(code))
    c["recon_cnt"] = len(PAT["recon"].findall(code))
    c["decode_exec_chain"] = len(CHAIN.findall(code))
    if install_time:                                  # everything an install script runs, runs at install
        for k in ("exec", "decode", "process", "network", "sensitive"):
            c[f"install_{k}"] = int(c[f"{k}_cnt"] > 0)
        c["auto_process"], c["auto_network"], c["auto_exec"] = len(proc_pos), len(net_pos), len(exec_pos)
    elif not big:
        top = lambda positions: sum(1 for p in positions if not _inside(bodies, starts, p))   # noqa: E731
        c["auto_process"], c["auto_network"], c["auto_exec"] = top(proc_pos), top(net_pos), top(exec_pos)
    return c


# ------------------------------------------------------------------------------------------ files of a package

def iter_archive(data, depth=0, budget=None, prefix=""):
    """(path, bytes) of the files with KEEP_SUFFIXES in an npm tarball or a sample zip (archives inside are opened,
    MAX_DEPTH levels). Nothing is written to disk."""
    budget = budget if budget is not None else [0, 0]
    bio = io.BytesIO(data)
    members = []
    if zipfile.is_zipfile(bio):
        z = zipfile.ZipFile(bio)
        z.setpassword(b"infected")                 # malware sample archives (training data)
        for info in z.infolist():
            if info.compress_type == AES_COMPRESS_TYPE:
                raise UnreadableArchive("AES-encrypted zip")
            if not info.is_dir() and info.file_size <= MAX_MEMBER:
                members.append((info.filename, info.file_size, lambda i=info: z.read(i)))
    else:
        _check_inflation(data, budget)
        bio.seek(0)                                    # is_zipfile() moved it to the end
        try:
            t = tarfile.open(fileobj=bio, mode="r:*")
        except tarfile.TarError:
            return
        for m in t.getmembers():
            if m.isfile() and m.size <= MAX_MEMBER:
                members.append((m.name, m.size, lambda m=m: t.extractfile(m).read()))
    for name, size, read in members:
        low = "/" + name.lower().replace("\\", "/")
        is_arc = low.endswith(ARCHIVE_EXT) and depth < MAX_DEPTH
        keep = low.endswith(KEEP_SUFFIXES)
        if not (keep or is_arc) or budget[0] > MAX_TOTAL:
            continue
        content = read()
        budget[0] += len(content)
        if is_arc and not keep:
            yield from iter_archive(content, depth + 1, budget, prefix + name + "!/")
        else:
            yield prefix + name.replace("\\", "/"), content


def iter_dir(root):
    """(path relative to root, bytes) of the files with KEEP_SUFFIXES under a folder the guard unpacked."""
    from pathlib import Path
    root = Path(root)
    total = 0
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        rel = p.relative_to(root).as_posix()
        if not ("/" + rel.lower()).endswith(KEEP_SUFFIXES) or "#" in p.name or ".." in rel:
            continue                                   # package.json#postinstall.sh: the guard's own copies
        size = p.stat().st_size
        if size > MAX_MEMBER or total > MAX_TOTAL:
            continue
        total += size
        yield rel, p.read_bytes()


def package_root(paths):
    """The folder of the shallowest package.json (npm tarballs: package/)."""
    roots = sorted((p.count("/"), posixpath.dirname(p)) for p in paths if posixpath.basename(p) == "package.json")
    return roots[0][1] if roots else ""


def norm(path, root):
    rel = posixpath.relpath(path, root) if root else path
    return posixpath.normpath(rel)


def code_features(files, install_files=(), inline_install_code=()):
    """The features of a package: files = [(path relative to the package root, text)], install_files = the paths the
    lifecycle scripts run, inline_install_code = `node -e` code of the lifecycle scripts."""
    f = {k: 0 for k in JS_CODE_FEATURES}
    install = set(install_files)
    sources = [(p, t, p in install) for p, t in files if p.lower().endswith(JS_SUFFIXES)]
    sources += [(f"<install script {k}>", t, True) for k, t in enumerate(inline_install_code)]
    # install-time code first, then the smallest files (attack code is small; bundles are large), then by path
    sources.sort(key=lambda s: (not s[2], len(s[1]), s[0]))
    budget = ANALYZE_BUDGET
    for _, text, at_install in sources:
        if at_install:                                 # code run at install is always read in full, outside the budget
            c = file_counts(text, True)
        elif len(text) <= budget:
            budget -= len(text)
            c = file_counts(text, False)
        else:
            budget = 0                                 # past the budget: the rest are only counted and measured
            c = size_counts(text)
        for k, v in c.items():
            if k == "max_line_len":
                f[k] = max(f[k], v)
            elif k.startswith("install_"):
                f[k] = max(f[k], v)
            else:
                f[k] += v
    hits = f["exec_cnt"] + f["decode_cnt"] + f["long_blob_cnt"] + f["obf_ident_cnt"]
    f["obfuscation_rate"] = hits / max(f["code_lines"], 1) * 1000
    return f
