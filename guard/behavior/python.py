"""Python front end of the behavior analysis: an abstract interpreter over the standard library `ast`. Nothing is run.

Values (values.Val) are rebuilt where the code makes them from constants: string / bytes / int operations, f-strings,
%, str methods, slices, decoders (base64, hex, zlib / bz2 / lzma, codecs, chr / ord, bytes), names reached through
import aliases, getattr with a computed name, __builtins__ and __import__, short local functions and lambdas called with
their arguments, comprehensions over known items. Where a value cannot be rebuilt it stays unknown but keeps its taint
tags and, for strings, a partial text with the unknown parts replaced by PH (so "curl " + url + " | sh" still reads).

Data flow: sources (network responses, credential files, the whole environment, secret-looking env vars, user / host
information, files of the package itself = LOCAL) tag values; tags follow assignments, containers, calls and method
calls. Sinks (code execution, process execution, network sends, file writes) turn tags and rebuilt values into the
findings of rules/behavior.json. A rebuilt code string is analyzed again (this module); a rebuilt command line goes to
shell.py.

Phases: the caller gives the file's phase. Top-level code runs at it, and so do the functions it calls (they are
evaluated with their arguments). Every function not reached that way is analyzed once more with unknown arguments at
"call" - or at the file's own phase for setup.py / startup files, where a cmdclass method runs at install too.
"""
from __future__ import annotations

import ast
import base64
import binascii
import bz2
import codecs
import lzma
import re
import shlex
import sys
import zlib

from . import LimitExceeded
from .values import (DECODED, LOCAL, NET, NOVAL, SECRET, SECRET_ENV, SYSINFO, Val, endpoint_class, is_secret_env,
                     path_class, wipe_target)

CRED_PATH, AUTOSTART_PATH, SOCK, NET_FILE, FILE = "CRED_PATH", "AUTOSTART_PATH", "SOCK", "NET_FILE", "FILE"
# unreadable_exec is judged on these (js.py has the same): OPAQUE = computed from constants by code the analysis could
# not follow (a custom decoder, a size limit); ENV = an environment variable's value (code handed in from outside)
OPAQUE, ENV = "OPAQUE", "ENV"
SOURCE_TAGS = {NET, SECRET, SECRET_ENV, SYSINFO, DECODED, LOCAL, FILE}
PH = "XUNKX"
RELEVANT = re.compile(r"exec|eval|compile|system|popen|subprocess|spawn|pty|socket|url|request|http|fetch|environ|getenv|"
                      r"b64|base64|b32|b85|hex|decode|decompress|marshal|pickle|loads|getattr|__import__|import_module|"
                      r"builtins|globals|vars\(|dup2|winreg|chmod|startfile|getuser|hostname|getlogin|node\(|uname|getcwd|"
                      r"open|write|Path|smtp|ftp|dns|chr\(|codecs|copy|move|rename|expanduser|home|send|post|upload|"
                      r"Thread|Process|atexit|run|call|cmd|shell|wget|curl")                                     # stands for an unknown part inside a partial string
AUTO = ("install", "interpreter_start", "import")

ALIASES = {"posix": "os", "nt": "os", "urllib2": "urllib.request", "urllib.urlopen": "urllib.request.urlopen",
           "urllib.urlretrieve": "urllib.request.urlretrieve", "commands": "subprocess", "__builtin__": "builtins",
           "_winreg": "winreg", "cPickle": "pickle", "_pickle": "pickle", "httplib": "http.client",
           "pathlib.PosixPath": "pathlib.Path", "pathlib.WindowsPath": "pathlib.Path", "pathlib.PurePath": "pathlib.Path",
           "pathlib.PurePosixPath": "pathlib.Path", "pathlib.PureWindowsPath": "pathlib.Path",
           "requests.api": "requests", "requests.sessions.Session": "requests.Session"}
BUILTINS = {"exec", "eval", "compile", "execfile", "getattr", "setattr", "hasattr", "vars", "globals", "locals",
            "__import__", "open", "chr", "ord", "bytes", "bytearray", "str", "repr", "int", "float", "bool", "list",
            "tuple", "set", "frozenset", "dict", "len", "sorted", "reversed", "map", "filter", "zip", "enumerate",
            "range", "sum", "min", "max", "abs", "hex", "oct", "bin", "round", "divmod", "pow", "any", "all", "iter",
            "next", "isinstance", "issubclass", "format", "print", "input", "type", "callable", "id", "hash", "super",
            "memoryview", "ascii", "object", "property", "staticmethod", "classmethod", "breakpoint", "help", "dir"}
CODE_EXEC = {"builtins.exec", "builtins.eval", "builtins.execfile", "builtins.compile"}
PROCESS = {"subprocess." + n for n in ("run", "call", "check_call", "check_output", "Popen", "getoutput",
                                       "getstatusoutput")} | \
          {"os." + n for n in ("system", "popen", "popen2", "popen3", "startfile", "execl", "execle", "execlp", "execlpe",
                               "execv", "execve", "execvp", "execvpe", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv",
                               "spawnve", "spawnvp", "spawnvpe", "posix_spawn", "posix_spawnp")} | \
          {"pty.spawn", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec", "platform.popen"}
DANGEROUS = CODE_EXEC | PROCESS | {"builtins.__import__", "marshal.loads", "pickle.loads", "importlib.import_module"}
SYSINFO_CALLS = {"getpass.getuser", "os.getlogin", "socket.gethostname", "socket.getfqdn", "platform.node",
                 "platform.uname", "os.uname", "os.getcwd", "os.getcwdb", "uuid.getnode", "pwd.getpwuid",
                 "pathlib.Path.cwd", "psutil.users"}
SYSINFO_ENV = {"USER", "USERNAME", "LOGNAME", "HOSTNAME", "COMPUTERNAME", "USERDOMAIN", "PWD"}
HOME_ENV = {"HOME": "~", "USERPROFILE": "~", "APPDATA": "~/appdata/roaming", "LOCALAPPDATA": "~/appdata/local",
            "HOMEPATH": "~", "TEMP": "/tmp", "TMP": "/tmp", "TMPDIR": "/tmp"}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "urlopen", "open"}
HTTP_MODULES = {"requests", "httpx", "urllib3", "aiohttp"}
IP_LOOKUP = re.compile(r"ipinfo\.io|ip-api\.com|ipify\.org|ifconfig\.me|icanhazip|checkip", re.I)
NEVER_LOCAL = set(getattr(sys, "stdlib_module_names", ())) | HTTP_MODULES | {"dns", "psutil", "wget", "dill",
                                                                              "cloudpickle", "setuptools", "distutils"}
SAFE_STR = {"join", "replace", "split", "rsplit", "strip", "lstrip", "rstrip", "lower", "upper", "casefold", "swapcase",
            "title", "capitalize", "encode", "decode", "startswith", "endswith", "find", "rfind", "index", "rindex",
            "count", "zfill", "center", "ljust", "rjust", "translate", "maketrans", "splitlines", "partition",
            "rpartition", "removeprefix", "removesuffix", "isdigit", "isalpha", "isalnum", "isspace", "isupper",
            "islower", "hex", "fromhex", "expandtabs", "format", "format_map", "isascii", "isidentifier"}
TEXT_CODECS = {"utf-8", "utf8", "utf_8", "ascii", "latin-1", "latin1", "iso-8859-1", "utf-16", "utf-16-le",
               "utf-16-be", "utf_16", "utf_16_le", "cp1252", "unicode_escape", "raw_unicode_escape", "utf-32", "idna"}
DECODE_CODECS = {"rot13", "rot_13", "hex", "hex_codec", "base64", "base64_codec", "zlib", "zlib_codec", "bz2",
                 "bz2_codec", "uu", "uu_codec", "quopri", "quopri_codec"}


class _Return(Exception):
    def __init__(self, val):
        self.val = val


class _Break(Exception):
    pass


class _Continue(Exception):
    pass


# --------------------------------------------------------------------------------------------------------- values

def V(c=NOVAL, tags=(), ref=None, **meta) -> Val:
    return Val(c, tags, ref, meta or None)


def M(v: Val, key, default=None):
    return v.meta.get(key, default) if isinstance(v.meta, dict) else default


def T(*vals) -> frozenset:
    out = set()
    for v in vals:
        if isinstance(v, Val):
            out |= v.tags
    return frozenset(out)


def text(v: Val):
    """Known text, or the partial text of an unknown string, else None."""
    s = v.s() if v.known else None
    return s if s is not None else M(v, "partial")


def cands(v: Val) -> list:
    """The known values v may hold (itself, or the alternatives of a merged value)."""
    if v.known:
        return [v]
    return [a for a in M(v, "alts", ()) if a.known]


def texts(v: Val) -> list:
    out = [text(a) for a in ([v] + list(M(v, "alts", ())))]
    return [t for t in out if isinstance(t, str)]


def conc(v: Val, depth=0):
    """The plain Python value of a known Val (containers recursively), else NOVAL."""
    if not isinstance(v, Val) or not v.known or depth > 20:
        return NOVAL
    c = v.c
    if isinstance(c, (list, tuple)):
        out = [conc(x, depth + 1) if isinstance(x, Val) else x for x in c]
        return NOVAL if any(x is NOVAL for x in out) else (tuple(out) if isinstance(c, tuple) else out)
    if isinstance(c, dict):
        out = {}
        for k, x in c.items():
            y = conc(x, depth + 1) if isinstance(x, Val) else x
            if y is NOVAL:
                return NOVAL
            out[k] = y
        return out
    return c


def merge(a: Val, b: Val) -> Val:
    if a is b:
        return a
    if a.known and b.known and type(a.c) is type(b.c) and isinstance(a.c, (str, bytes, int, float, bool, type(None))) \
            and a.c == b.c:
        return a if a.tags >= b.tags else Val(a.c, a.tags | b.tags, a.ref, a.meta)
    if (a.ref == "os.environ") != (b.ref == "os.environ"):   # `env or dict(os.environ)`: still read by name
        e = a if a.ref == "os.environ" else b
        return Val(NOVAL, a.tags | b.tags, "os.environ", e.meta)
    if a.ref and not b.ref and not b.known:
        return Val(a.c, a.tags | b.tags, a.ref, a.meta)
    if b.ref and not a.ref and not a.known:
        return Val(b.c, a.tags | b.tags, b.ref, b.meta)
    if a.ref and a.ref == b.ref and a.ref[:1] != "#":
        return Val(NOVAL, a.tags | b.tags, a.ref, a.meta)
    alts = []
    for x in (a, b):
        for y in ([x] if x.known else []) + list(M(x, "alts", ())):
            if len(alts) < 16 and not any(y is z for z in alts):
                alts.append(y)
    partial = M(a, "partial") or M(b, "partial")
    meta = {}
    if alts:
        meta["alts"] = alts
    if partial:
        meta["partial"] = partial
    return Val(NOVAL, a.tags | b.tags, None, meta or None)


def path_tags(s) -> frozenset:
    c = path_class(s) if isinstance(s, str) else None
    return frozenset({CRED_PATH} if c == "credential" else {AUTOSTART_PATH} if c == "autostart" else ())


def _size_ok(x, lim) -> bool:
    if isinstance(x, (str, bytes, bytearray)):
        return len(x) <= lim["max_string"]
    if isinstance(x, int) and not isinstance(x, bool):
        return x.bit_length() <= 65536
    if isinstance(x, (list, tuple, dict, set, frozenset)):
        return len(x) <= lim["max_iter"]
    return True


def wrap(x, tags=frozenset(), lim=None) -> Val:
    """A Val of a plain Python result (over a size limit: unknown, and opaque - constants made it)."""
    if lim is not None and not _size_ok(x, lim):
        return V(NOVAL, frozenset(tags) | {OPAQUE})
    if isinstance(x, (list, tuple, set, frozenset)):
        items = [wrap(i, tags) for i in x]
        return Val(tuple(items) if isinstance(x, tuple) else items, tags)
    if isinstance(x, dict):
        return Val({k: wrap(i, tags) for k, i in x.items()}, tags)
    if isinstance(x, bytearray):
        x = bytes(x)
    if isinstance(x, (str, bytes, int, float, bool, type(None), complex)):
        return Val(x, tags)
    return V(NOVAL, tags)


def canon(ref: str | None) -> str | None:
    if not ref:
        return ref
    for a, b in ALIASES.items():
        if b and (ref == a or ref.startswith(a + ".")):
            return b + ref[len(a):]
    return ref


def _limited_decompress(fn, data: bytes, lim) -> bytes | None:
    try:
        if fn == "zlib":
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 32):
                try:
                    d = zlib.decompressobj(wbits)
                    out = d.decompress(data, lim)
                    return out if not d.unconsumed_tail else None
                except zlib.error:
                    continue
            return None
        d = bz2.BZ2Decompressor() if fn == "bz2" else lzma.LZMADecompressor()
        out = d.decompress(data, lim)
        return out if d.eof or not d.needs_input else out
    except Exception:
        return None


def _fmt_ok(fmt: str) -> bool:
    """No huge widths / precisions in a format string (they would allocate megabytes)."""
    return not re.search(r"\d{6,}", fmt) and fmt.count("{") < 2000


# --------------------------------------------------------------------------------------------------------- scopes

class Scope:
    __slots__ = ("vars", "parent", "globs", "self_val", "cls")

    def __init__(self, parent=None, self_val=None, cls=None):
        self.vars: dict = {}
        self.parent = parent
        self.globs: set = set()
        self.self_val = self_val
        self.cls = cls

    def get(self, name):
        s = self
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        return None

    def module(self):
        s = self
        while s.parent is not None:
            s = s.parent
        return s

    def set(self, name, v):
        (self.module() if name in self.globs else self).vars[name] = v


class Func:
    __slots__ = ("node", "scope", "interp", "cls", "name")

    def __init__(self, node, scope, interp, cls=None):
        self.node, self.scope, self.interp, self.cls = node, scope, interp, cls
        self.name = getattr(node, "name", "<lambda>")


class ClassInfo:
    __slots__ = ("name", "scope", "attrs")

    def __init__(self, name, scope):
        self.name, self.scope, self.attrs = name, scope, {}


class Shared:
    """State shared by the interpreters of one package (all files, nested code)."""

    def __init__(self):
        self.call_depth = 0
        self.cache: dict = {}
        self.entered: set = set()
        self.file_tags: dict = {}          # normalized path -> tags of the data written there
        self.load_depth = 0


def _shared(ctx) -> Shared:
    sh = getattr(ctx, "_py_shared", None)
    if sh is None:
        sh = Shared()
        ctx._py_shared = sh
    return sh


# --------------------------------------------------------------------------------------------------------- interpreter

class Interp:
    def __init__(self, ctx, file: str, phase: str, depth=0, line_base=None, source=""):
        self.ctx, self.file, self.phase, self.depth, self.line_base = ctx, file, phase, depth, line_base
        self.lim = ctx.limits
        self.sh = _shared(ctx)
        self.steps = 0
        self.iters = 0
        self.funcs: list[Func] = []
        self.loaded = False                 # imported by other code being analyzed (load_module), not a planned file
        self.source = source
        self.lines = source.splitlines() if source else []
        self._blines = None
        self.glob = Scope()
        self.pkg = ".".join(file.split("/")[:-1])          # the package a relative import starts from
        g = self.glob.vars
        g["__builtins__"] = V(ref="builtins")
        g["__file__"] = Val(file)
        g["__name__"] = V("__main__" if phase in ("install", "command") else (file[:-3].replace("/", ".") or "module"))

    # ----------------------------------------------------------------- bookkeeping
    def tick(self, n=1):
        self.steps += n
        if self.steps > self.lim["max_steps"]:
            raise LimitExceeded("step limit")
        if self.steps % 2000 == 0:
            self.ctx.check_time()

    def line(self, node) -> int:
        return self.line_base or getattr(node, "lineno", 1)

    def emit(self, finding, ph, node, detail=""):
        if not detail and node is not None and self.lines:
            ln = getattr(node, "lineno", 0)
            if 0 < ln <= len(self.lines):
                detail = self.lines[ln - 1].strip()
        self.ctx.emit(finding, ph, self.file, self.line(node), detail)

    def src(self, node) -> str:
        """Source text of a one-line node (ast.get_source_segment re-splits the whole file on every call)."""
        ln, end = getattr(node, "lineno", 0), getattr(node, "end_lineno", 0)
        if not ln or ln != end or ln > len(self.lines):
            return ""
        if self._blines is None:
            self._blines = {}
        b = self._blines.get(ln)
        if b is None:
            b = self._blines[ln] = self.lines[ln - 1].encode("utf-8", "surrogatepass")
        try:
            return b[node.col_offset:node.end_col_offset].decode("utf-8")
        except (UnicodeDecodeError, TypeError):
            return ""

    # ----------------------------------------------------------------- module
    def run_module(self, tree, env=None, defer=False):
        if env:
            for k, v in env.items():
                self.glob.vars.setdefault(k, v)
        self.block(tree.body, self.glob, self.phase, definite=True)
        if defer:
            self.ctx.py_pending.append(self)    # after every file's top level ran (it may call into this file)
        else:
            self.leftovers()

    def leftovers(self):
        ph = self.phase if self.phase in ("install", "interpreter_start", "command") else "call"
        if self.loaded:
            ph = "call"      # a module setup.py imports: its top level ran at install, its functions run when called
        done = 0
        while done < len(self.funcs):
            fn = self.funcs[done]
            done += 1
            if id(fn.node) in self.sh.entered:
                continue
            if ph == "call" and not self.relevant(fn.node):
                continue
            args = fn.node.args
            n = len(args.posonlyargs) + len(args.args)
            static = any(isinstance(d, ast.Name) and d.id == "staticmethod" for d in fn.node.decorator_list)
            self_val = V(ref="#inst", cls=fn.cls) if fn.cls is not None and not static else None
            try:
                self.invoke(fn, [Val() for _ in range(n - (1 if self_val else 0))], {}, ph, self_val, force=True)
            except LimitExceeded:
                raise
            except (RecursionError, MemoryError):
                continue

    def relevant(self, node) -> bool:
        """A function that names nothing a finding can come from (no sink, source, decoder or dynamic name) cannot
        make a fact by itself; at "call" it is skipped (numeric and parsing code is most of a large package)."""
        a, b = getattr(node, "lineno", 0), getattr(node, "end_lineno", 0)
        if not a or not b:
            return True
        return RELEVANT.search("\n".join(self.lines[a - 1:b])) is not None

    # ----------------------------------------------------------------- statements
    def block(self, stmts, sc, ph, definite=True):
        for st in stmts:
            if definite:
                self.stmt(st, sc, ph)
            else:
                try:
                    self.stmt(st, sc, ph)
                except _Return:
                    return
                except (_Break, _Continue):
                    return

    def branch(self, bodies, sc, ph):
        """Run alternative bodies (an if with an unknown test, try handlers) on copies and merge what they bind."""
        outs = []
        for body in bodies:
            s2 = Scope(sc.parent, sc.self_val, sc.cls)
            s2.vars = dict(sc.vars)
            s2.globs = sc.globs
            try:
                self.block(body, s2, ph, definite=True)
            except _Return as r:
                self._record_return(sc, r.val)
            except (_Break, _Continue):
                pass
            outs.append(s2.vars)
        keys = set().union(*outs) if outs else set()
        for k in keys:
            vals = [o[k] for o in outs if k in o]
            if k in sc.vars and len(vals) < len(outs):
                vals.append(sc.vars[k])
            v = vals[0]
            for w in vals[1:]:
                v = merge(v, w)
            sc.vars[k] = v

    def _record_return(self, sc, v):
        rets = sc.vars.get("#returns")
        if isinstance(rets, list):
            rets.append(v)

    def stmt(self, st, sc, ph):
        self.tick()
        try:
            self._stmt(st, sc, ph)
        except (_Return, _Break, _Continue, LimitExceeded):
            raise
        except RecursionError:
            pass
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, OverflowError, ZeroDivisionError,
                UnicodeError, AssertionError) as e:  # noqa: F841 - a value the analysis could not combine
            pass

    def _stmt(self, st, sc, ph):
        if isinstance(st, ast.Expr):
            self.ev(st.value, sc, ph)
        elif isinstance(st, ast.Assign):
            v = self.ev(st.value, sc, ph)
            for t in st.targets:
                self.assign(t, v, sc, ph)
        elif isinstance(st, ast.AnnAssign):
            if st.value is not None:
                self.assign(st.target, self.ev(st.value, sc, ph), sc, ph)
        elif isinstance(st, ast.AugAssign):
            cur = self.ev(st.target, sc, ph) if not isinstance(st.target, ast.Name) or sc.get(st.target.id) else Val()
            self.assign(st.target, self.binop(st.op, cur, self.ev(st.value, sc, ph)), sc, ph)
        elif isinstance(st, (ast.Import, ast.ImportFrom)):
            self.imp(st, sc, ph)
        elif isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fn = Func(st, sc, self, sc.cls)
            self.funcs.append(fn)
            fv = V(ref="#func", func=fn)
            for d in st.decorator_list:
                dv = self.ev(d, sc, ph)
                if canon(dv.ref) in ("atexit.register",) or M(dv, "invokes"):
                    self.invoke(fn, [], {}, ph)
            sc.vars[st.name] = fv
        elif isinstance(st, ast.ClassDef):
            for b in st.bases:
                self.ev(b, sc, ph)
            ci = ClassInfo(st.name, Scope(sc, cls=None))
            ci.scope.cls = ci
            cv = V(ref="#class", cls=ci)
            sc.vars[st.name] = cv
            self.block(st.body, ci.scope, ph, definite=False)
        elif isinstance(st, ast.Return):
            v = self.ev(st.value, sc, ph) if st.value is not None else Val(None)
            raise _Return(v)
        elif isinstance(st, ast.If):
            self.if_(st, sc, ph)
        elif isinstance(st, (ast.For, ast.AsyncFor)):
            self.for_(st, sc, ph)
        elif isinstance(st, ast.While):
            self.ev(st.test, sc, ph)
            self.branch([st.body + st.orelse], sc, ph)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            for item in st.items:
                v = self.ev(item.context_expr, sc, ph)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, v, sc, ph)
            self.block(st.body, sc, ph, definite=True)
        elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
            try:
                self.block(st.body, sc, ph, definite=True)
            except (_Break, _Continue):
                raise
            handlers = []
            for h in st.handlers:
                if h.name:
                    handlers.append([ast.Assign(targets=[ast.Name(h.name, ast.Store())], value=ast.Constant(None),
                                                lineno=h.lineno, col_offset=0)] + h.body)
                else:
                    handlers.append(h.body)
            if handlers:
                self.branch(handlers + [[]], sc, ph)
            self.block(st.orelse, sc, ph, definite=False)
            self.block(st.finalbody, sc, ph, definite=True)
        elif isinstance(st, ast.Global) or isinstance(st, ast.Nonlocal):
            if isinstance(st, ast.Global):
                sc.globs.update(st.names)
        elif isinstance(st, ast.Raise):
            if st.exc is not None:
                self.ev(st.exc, sc, ph)
        elif isinstance(st, ast.Break):
            raise _Break()
        elif isinstance(st, ast.Continue):
            raise _Continue()
        elif isinstance(st, ast.Delete):
            pass
        elif isinstance(st, ast.Assert):
            self.ev(st.test, sc, ph)
        elif type(st).__name__ == "Match":
            self.ev(st.subject, sc, ph)
            self.branch([c.body for c in st.cases] + [[]], sc, ph)

    def if_(self, st, sc, ph):
        # `if __name__ == "__main__":` in an imported module runs only when the file is run as a script
        t = st.test
        if (isinstance(t, ast.Compare) and isinstance(t.left, ast.Name) and t.left.id == "__name__"
                and len(t.comparators) == 1 and isinstance(t.comparators[0], ast.Constant)
                and t.comparators[0].value == "__main__" and isinstance(t.ops[0], ast.Eq)):
            if ph == "import":
                self.branch([st.body], sc, "command")
                self.block(st.orelse, sc, ph, definite=False)
                return
            if ph == "install":
                self.block(st.body, sc, ph, definite=True)
                return
        tv = self.ev(t, sc, ph)
        c = conc(tv)
        if c is not NOVAL and not isinstance(c, (list, dict)) and tv.ref is None:
            self.block(st.body if c else st.orelse, sc, ph, definite=True)
        else:
            self.branch([st.body, st.orelse], sc, ph)

    def iter_items(self, v: Val):
        if not v.known:
            return None
        c = v.c
        if isinstance(c, str):
            return [Val(ch, v.tags) for ch in c] if len(c) <= self.lim["max_iter"] else None
        if isinstance(c, bytes):
            return [Val(b, v.tags) for b in c] if len(c) <= self.lim["max_iter"] else None
        if isinstance(c, (list, tuple)):
            return list(c)
        if isinstance(c, dict):
            return [V(k, v.tags) for k in c]
        return None

    def for_(self, st, sc, ph):
        it = self.ev(st.iter, sc, ph)
        items = self.iter_items(it)
        if items is not None and len(items) <= 256 and self.iters + len(items) <= self.lim["max_iter"]:
            try:
                for item in items:
                    self.iters += 1
                    self.tick()
                    self.assign(st.target, item, sc, ph)
                    try:
                        self.block(st.body, sc, ph, definite=True)
                    except _Continue:
                        continue
                else:
                    self.block(st.orelse, sc, ph, definite=False)
            except _Break:
                pass
            return
        elem = self.element(it)
        self.assign(st.target, elem, sc, ph)
        self.branch([st.body + st.orelse], sc, ph)

    def element(self, it: Val) -> Val:
        """An unknown element of an iterable (taint of the iterable; the environment's items are secret)."""
        if it.ref == "os.environ":
            return V(NOVAL, {SECRET}, environ=True)
        if M(it, "partial") or CRED_PATH in it.tags:
            return V(NOVAL, it.tags, partial=M(it, "partial"))
        items = self.iter_items(it)
        if items:
            v = items[0]
            for w in items[1:16]:
                v = merge(v, w)
            return v
        alts = M(it, "alts")
        if alts:
            v = Val(NOVAL, it.tags)
            for a in alts:
                for x in (self.iter_items(a) or [])[:16]:
                    v = merge(v, x)
            return v
        return V(NOVAL, it.tags - {SOCK}, src=it)

    # ----------------------------------------------------------------- assignment
    def assign(self, t, v: Val, sc, ph):
        if isinstance(t, ast.Name):
            sc.set(t.id, v)
        elif isinstance(t, (ast.Tuple, ast.List)):
            items = self.iter_items(v) if v.known and isinstance(v.c, (list, tuple)) else None
            star = next((i for i, e in enumerate(t.elts) if isinstance(e, ast.Starred)), None)
            if items is not None and (len(items) == len(t.elts) or star is not None):
                if star is None:
                    for e, x in zip(t.elts, items):
                        self.assign(e, x, sc, ph)
                else:
                    after = len(t.elts) - star - 1
                    for e, x in zip(t.elts[:star], items):
                        self.assign(e, x, sc, ph)
                    mid = items[star:len(items) - after]
                    self.assign(t.elts[star].value, Val(list(mid), T(*mid)), sc, ph)
                    for e, x in zip(t.elts[star + 1:], items[len(items) - after:]):
                        self.assign(e, x, sc, ph)
            else:
                elem = self.element(v)
                for i, e in enumerate(t.elts):
                    target = e.value if isinstance(e, ast.Starred) else e
                    if M(v, "pair") and i < len(M(v, "pair")):
                        self.assign(target, M(v, "pair")[i], sc, ph)
                    else:
                        self.assign(target, elem, sc, ph)
        elif isinstance(t, ast.Starred):
            self.assign(t.value, v, sc, ph)
        elif isinstance(t, ast.Attribute):
            base = self.ev(t.value, sc, ph)
            ci = M(base, "cls")
            if isinstance(ci, ClassInfo):
                ci.attrs[t.attr] = v
            elif M(base, "file") is not None and t.attr == "name":
                pass
            elif isinstance(M(base, "obj"), dict):
                M(base, "obj")[t.attr] = v
            elif isinstance(t.value, ast.Name) and base.ref is None:
                key = f"{t.value.id}.{t.attr}"
                sc.set(key, v)
        elif isinstance(t, ast.Subscript):
            base = self.ev(t.value, sc, ph)
            key = self.ev(t.slice, sc, ph)
            if base.known and isinstance(base.c, dict) and key.known and isinstance(key.c, (str, int, bytes)):
                base.c[key.c] = v
                base.tags = base.tags | v.tags
            elif base.known and isinstance(base.c, list) and key.known and isinstance(key.c, int):
                try:
                    base.c[key.c] = v
                    base.tags = base.tags | v.tags
                except IndexError:
                    pass
            elif base.ref == "os.environ":
                pass
            elif v.tags - {LOCAL} and isinstance(t.value, ast.Name):
                cur = sc.get(t.value.id)
                if cur is not None and cur.ref is None:
                    try:
                        cur.tags = cur.tags | v.tags
                    except AttributeError:
                        pass

    # ----------------------------------------------------------------- imports
    def local_module(self, name: str):
        if not name or name.split(".")[0] in NEVER_LOCAL:
            return None
        return name if name in self.ctx.modules else None

    def load_module(self, name: str, ph: str) -> Val:
        """A package module imported by this code: its top level runs (once per phase) and its names are reachable."""
        parts = name.split(".")
        for i in range(1, len(parts)):                   # importing a.b.c runs a/__init__.py and a/b/__init__.py first
            parent = ".".join(parts[:i])
            if parent in self.ctx.modules:
                self.load_module(parent, ph)
        path, rel = self.ctx.modules[name]
        mph = ph if ph in ("install", "interpreter_start") else "import"
        if rel in self.ctx.held and ph not in AUTO:
            mph = "call"                     # a test module a function imports runs when that function is called
        key = (rel, mph)
        interp = self.ctx.py_scopes.get(key)
        if interp is None and key not in self.ctx.module_phases and self.sh.load_depth < 8:
            text_ = self.ctx.read_python(path, rel, mph)
            if text_ is None:
                self.ctx.module_phases.add(key)
                self.ctx.unread(rel, mph, "size limit")
            else:
                self.ctx.module_phases.add(key)
                self.sh.load_depth += 1
                try:
                    analyze_source(self.ctx, text_, rel, mph, loaded=True)
                except LimitExceeded as e:
                    self.ctx.unread(rel, mph, str(e))
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    pass
                finally:
                    self.sh.load_depth -= 1
                interp = self.ctx.py_scopes.get(key)
        return V(ref="#mod", mod=name, interp=interp)

    def imp(self, st, sc, ph):
        if isinstance(st, ast.Import):
            for a in st.names:
                local = self.local_module(a.name)
                if local:
                    mv = self.load_module(local, ph)
                    if a.asname:
                        sc.set(a.asname, mv)
                    else:
                        top = a.name.split(".")[0]
                        sc.set(top, self.load_module(top, ph) if top in self.ctx.modules else V(ref="#mod", mod=top))
                else:
                    sc.set(a.asname or a.name.split(".")[0], V(ref=canon(a.name if a.asname else a.name.split(".")[0])))
            return
        mod = st.module or ""
        if st.level:
            base = self.pkg.split(".") if self.pkg else []
            up = st.level - 1
            base = base[:len(base) - up] if up else base
            mod = ".".join([p for p in base if p] + ([mod] if mod else []))
        local = self.local_module(mod) if mod else None
        for a in st.names:
            if a.name == "*":
                if local:
                    mv = self.load_module(local, ph)
                    interp = M(mv, "interp")
                    if interp is not None:
                        for k, v in interp.glob.vars.items():
                            if not k.startswith("_"):
                                sc.set(k, v)
                else:
                    stars = sc.module().vars.setdefault("#stars", V([], ()))
                    stars.c.append(canon(mod))
                continue
            name = a.asname or a.name
            sub = f"{mod}.{a.name}" if mod else a.name
            if local or (st.level and self.local_module(sub)):
                if self.local_module(sub):
                    sc.set(name, self.load_module(sub, ph))
                    continue
                mv = self.load_module(local, ph)
                interp = M(mv, "interp")
                v = interp.glob.vars.get(a.name) if interp is not None else None
                sc.set(name, v if v is not None else Val())
            elif st.level:
                sc.set(name, Val())
            else:
                sc.set(name, V(ref=canon(sub)))

    # ----------------------------------------------------------------- expressions
    def ev(self, node, sc, ph) -> Val:
        if node is None:
            return Val(None)
        self.tick()
        try:
            return self._ev(node, sc, ph)
        except (_Return, _Break, _Continue, LimitExceeded):
            raise
        except RecursionError:
            return Val()
        except (ValueError, TypeError, AttributeError, KeyError, IndexError, OverflowError, ZeroDivisionError,
                UnicodeError, MemoryError, SystemError, LookupError):
            return Val()

    def _ev(self, node, sc, ph) -> Val:
        if isinstance(node, ast.Constant):
            return Val(node.value)
        if isinstance(node, ast.Name):
            return self.name(node.id, sc)
        if isinstance(node, ast.Attribute):
            return self.attr(self.ev(node.value, sc, ph), node.attr, node, sc)
        if isinstance(node, ast.Call):
            return self.call(node, sc, ph)
        if isinstance(node, ast.BinOp):
            return self.binop_chain(node, sc, ph)
        if isinstance(node, ast.JoinedStr):
            return self.fstring(node, sc, ph)
        if isinstance(node, ast.FormattedValue):
            return self.fstring(ast.JoinedStr([node]), sc, ph)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            items = []
            for e in node.elts:
                if isinstance(e, ast.Starred):
                    v = self.ev(e.value, sc, ph)
                    sub = self.iter_items(v)
                    items.extend(sub if sub is not None else [self.element(v)])
                else:
                    items.append(self.ev(e, sc, ph))
            return Val(tuple(items) if isinstance(node, ast.Tuple) else items, T(*items))
        if isinstance(node, ast.Dict):
            d, tags, ok = {}, set(), True
            for k, x in zip(node.keys, node.values):
                xv = self.ev(x, sc, ph)
                tags |= xv.tags
                if k is None:
                    if xv.ref == "os.environ":
                        tags.add(SECRET)
                    if xv.known and isinstance(xv.c, dict):
                        d.update(xv.c)
                    continue
                kv = self.ev(k, sc, ph)
                tags |= kv.tags
                if kv.known and isinstance(kv.c, (str, int, bytes, float, bool, type(None))):
                    d[kv.c] = xv
                else:
                    ok = False
            return Val(d, tags) if ok else V(NOVAL, tags)
        if isinstance(node, ast.Subscript):
            return self.subscript(self.ev(node.value, sc, ph), node.slice, sc, ph)
        if isinstance(node, ast.Slice):
            parts = [self.ev(x, sc, ph) if x is not None else Val(None) for x in (node.lower, node.upper, node.step)]
            cs = [conc(p) for p in parts]
            return Val(slice(*cs)) if all(c is not NOVAL for c in cs) else Val()
        if isinstance(node, ast.Compare):
            left = self.ev(node.left, sc, ph)
            rights = [self.ev(c, sc, ph) for c in node.comparators]
            vals = [conc(left)] + [conc(r) for r in rights]
            if all(x is not NOVAL for x in vals) and all(isinstance(x, (str, bytes, int, float, bool, type(None), tuple,
                                                                         list)) for x in vals):
                ok = True
                for op, a, b in zip(node.ops, vals, vals[1:]):
                    ok = ok and _compare(op, a, b)
                return Val(bool(ok))
            return Val()
        if isinstance(node, ast.BoolOp):
            vals = [self.ev(x, sc, ph) for x in node.values]
            for v in vals:
                c = conc(v)
                if c is NOVAL or v.ref:
                    break
                if isinstance(node.op, ast.Or) and c:
                    return v
                if isinstance(node.op, ast.And) and not c:
                    return v
            else:
                return vals[-1]
            out = vals[0]
            for w in vals[1:]:
                out = merge(out, w)
            return out
        if isinstance(node, ast.UnaryOp):
            v = self.ev(node.operand, sc, ph)
            c = conc(v)
            if c is NOVAL:
                return V(NOVAL, v.tags) if not isinstance(node.op, ast.Not) else Val()
            ops = {ast.Not: lambda x: not x, ast.USub: lambda x: -x, ast.UAdd: lambda x: +x, ast.Invert: lambda x: ~x}
            return wrap(ops[type(node.op)](c), v.tags)
        if isinstance(node, ast.IfExp):
            tv = self.ev(node.test, sc, ph)
            c = conc(tv)
            if c is not NOVAL and tv.ref is None and not isinstance(c, (list, dict)):
                return self.ev(node.body if c else node.orelse, sc, ph)
            return merge(self.ev(node.body, sc, ph), self.ev(node.orelse, sc, ph))
        if isinstance(node, ast.Lambda):
            return V(ref="#func", func=Func(node, sc, self, None))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self.comp(node, sc, ph)
        if isinstance(node, (ast.Await, ast.YieldFrom)):
            return self.ev(node.value, sc, ph)
        if isinstance(node, ast.Yield):
            v = self.ev(node.value, sc, ph) if node.value is not None else Val(None)
            self._record_return(sc, v)
            return Val()
        if isinstance(node, ast.NamedExpr):
            v = self.ev(node.value, sc, ph)
            self.assign(node.target, v, sc, ph)
            return v
        if isinstance(node, ast.Starred):
            return self.ev(node.value, sc, ph)
        return Val()

    def name(self, n: str, sc) -> Val:
        v = sc.get(n)
        if v is not None:
            return v
        if n in BUILTINS:
            return V(ref="builtins." + n)
        stars = sc.module().vars.get("#stars")
        if stars is not None and stars.c:
            mod = stars.c[-1]
            return V(ref=f"{mod}.{n}")
        return Val()

    def attr(self, base: Val, a: str, node, sc) -> Val:
        ref = base.ref
        hidden = M(base, "hidden")
        if ref == "#mod":
            interp = M(base, "interp")
            name = f"{M(base, 'mod')}.{a}"
            if interp is not None and a in interp.glob.vars:
                return interp.glob.vars[a]
            if self.local_module(name):
                return self.load_module(name, self.phase)
            return Val()
        if ref == "#inst" or ref == "#class":
            ci = M(base, "cls")
            if isinstance(ci, ClassInfo):
                if a in ci.attrs:
                    return ci.attrs[a]
                v = ci.scope.vars.get(a)
                if v is not None:
                    fn = M(v, "func")
                    if fn is not None and ref == "#inst":
                        return V(ref="#func", func=fn, bound=base)
                    return v
            return V(ref="#meth", self=base, name=a)
        if ref and ref[0] != "#":
            full = canon(f"{ref}.{a}")
            if re.fullmatch(r"ctypes\.(cdll|pydll|windll|oledll)\.\w+", full) and a != "LoadLibrary":
                return V(ref="#dll")                 # ctypes.cdll.msvcrt: a loaded C library
            if full == "os.environ":
                return V(NOVAL, {SECRET}, "os.environ")
            if full == "sys.executable":
                return Val("python")
            if full in ("os.sep",):
                return Val("/")
            if full == "os.linesep":
                return Val("\n")
            if full == "os.curdir":
                return Val(".")
            if full in ("os.name", "sys.platform", "sys.version", "sys.argv", "sys.prefix"):
                return Val()
            if full == "sys.path":
                return V(ref=full)                   # unknown, but sys.path.insert / append still reach their handler
            return V(ref=full, hidden=True) if hidden else V(ref=full)
        if ref == "#path":
            p = base.s() or M(base, "partial") or ""
            if a == "parent":
                return self.mkpath(p.rstrip("/").rsplit("/", 1)[0] if "/" in p.rstrip("/") else ".", base)
            if a in ("name", "stem", "suffix"):
                last = p.rstrip("/").rsplit("/", 1)[-1]
                if a == "stem":
                    last = last.rsplit(".", 1)[0]
                if a == "suffix":
                    last = "." + last.rsplit(".", 1)[1] if "." in last else ""
                return Val(last, base.tags) if base.known else V(NOVAL, base.tags)
        if ref == "#loader" and a == "loader":
            return base
        if ref == "#dll":
            return V(ref=LIBC[a]) if a in LIBC else V(ref="#dll")
        if ref == "#file" and a == "name":
            pv = M(base, "path") or Val()
            extra = {NET_FILE} if NET in M(base, "written", frozenset()) else set()
            return Val(pv.c, pv.tags | extra, None, pv.meta)
        if ref == "#func" and M(base, "func") is not None and a in ("__call__",):
            return base
        if base.known and isinstance(base.c, dict) and a in ("get", "items", "keys", "values", "update", "setdefault",
                                                              "pop", "copy"):
            return V(ref="#meth", self=base, name=a)
        tags = base.tags if ref != "os.environ" else frozenset()
        return V(NOVAL, tags, "#meth", self=base, name=a)

    def mkpath(self, p, *srcs) -> Val:
        tags = T(*srcs) | path_tags(p)
        if isinstance(p, str) and PH in p:
            return V(NOVAL, tags, "#path", partial=p)
        return Val(p, tags, "#path") if isinstance(p, str) else V(NOVAL, tags, "#path")

    def subscript(self, base: Val, sl, sc, ph) -> Val:
        key = self.ev(sl, sc, ph)
        kc = conc(key)
        if base.ref == "os.environ":
            return self.env_get(key)
        if base.ref in ("sys.modules",) and isinstance(kc, str):
            return V(ref=canon(kc), hidden=True)
        if base.ref in ("builtins", "builtins.__dict__") and isinstance(kc, str):
            return V(ref="builtins." + kc, hidden=True)
        if base.ref == "#globals" and isinstance(kc, str):
            v = self.name(kc, sc)
            return Val(v.c, v.tags, v.ref, dict(v.meta or {}, hidden=True)) if v.ref else v
        if base.ref == "#vars" and isinstance(kc, str):
            inner = M(base, "of")
            if inner is not None and inner.ref:
                return V(ref=canon(f"{inner.ref}.{kc}") if inner.ref != "builtins" else "builtins." + kc, hidden=True)
        if base.known and kc is not NOVAL:
            c = base.c
            try:
                if isinstance(c, (str, bytes)):
                    r = c[kc]
                    return Val(r, base.tags) if _size_ok(r, self.lim) else V(NOVAL, base.tags)
                if isinstance(c, (list, tuple)):
                    r = c[kc]
                    if isinstance(kc, slice):
                        return Val(list(r) if isinstance(c, list) else tuple(r), base.tags)
                    return r if isinstance(r, Val) else wrap(r, base.tags)
                if isinstance(c, dict):
                    r = c.get(kc)
                    return r if isinstance(r, Val) else (Val() if r is None else wrap(r, base.tags))
            except (IndexError, TypeError, ValueError, KeyError):
                return V(NOVAL, base.tags)
        if M(base, "partial") and isinstance(kc, slice):
            return V(NOVAL, base.tags)
        if base.ref == "#meth" and M(base, "name") == "__dict__":
            owner = M(base, "self")
            if owner is not None and owner.ref in ("builtins",) and isinstance(kc, str):
                return V(ref="builtins." + kc, hidden=True)
        alts = M(base, "alts")
        if alts and kc is not NOVAL:
            out = None
            for a in alts:
                r = self.subscript(a, ast.Constant(kc), sc, ph)
                out = r if out is None else merge(out, r)
            if out is not None:
                return out
        return V(NOVAL, base.tags - {SOCK} if base.ref != "os.environ" else frozenset())

    def env_get(self, key: Val, default: Val | None = None) -> Val:
        names = [c.c for c in cands(key) if isinstance(c.c, str)]
        if not names:
            return V(NOVAL, default.tags if default else ())
        n = names[0]
        if n.upper() in HOME_ENV:
            return Val(HOME_ENV[n.upper()])
        if n.upper() in SYSINFO_ENV:
            return V(NOVAL, {SYSINFO})
        if is_secret_env(n):
            return V(NOVAL, {SECRET_ENV}, None, envname=n)
        return V(NOVAL, {ENV})                 # set by whoever runs the code: unknown even with a default

    # ----------------------------------------------------------------- operators and strings
    def binop_chain(self, node, sc, ph) -> Val:
        # left-deep chains of + (long string concatenations) iteratively, not by recursion
        chain = []
        cur = node
        while isinstance(cur, ast.BinOp) and isinstance(cur.op, ast.Add) and len(chain) < 100000:
            chain.append(cur.right)
            cur = cur.left
        if chain and isinstance(node.op, ast.Add):
            acc = self.ev(cur, sc, ph)
            for right in reversed(chain):
                acc = self.binop(ast.Add(), acc, self.ev(right, sc, ph))
            return acc
        return self.binop(node.op, self.ev(node.left, sc, ph), self.ev(node.right, sc, ph))

    def binop(self, op, a: Val, b: Val) -> Val:
        tags = a.tags | b.tags
        if a.ref == "#path" and isinstance(op, ast.Div):
            pa, pb = text(a) or PH, text(b) or PH
            return self.mkpath(pb if pb.startswith(("/", "~")) else pa.rstrip("/") + "/" + pb, a, b)
        ca, cb = conc(a), conc(b)
        if ca is not NOVAL and cb is not NOVAL:
            if isinstance(op, ast.Mod) and isinstance(ca, (str, bytes)):
                if isinstance(ca, str) and not _fmt_ok(ca):
                    return V(NOVAL, tags)
                return wrap(ca % cb, tags, self.lim)
            if isinstance(op, ast.Mult):
                n = cb if isinstance(cb, int) else ca if isinstance(ca, int) else None
                seq = ca if not isinstance(ca, int) else cb
                if n is not None and hasattr(seq, "__len__") and len(seq) * max(n, 0) > self.lim["max_string"]:
                    return V(NOVAL, tags)
            if isinstance(op, (ast.LShift, ast.Pow)) and isinstance(cb, int) and (cb > 4096 or cb < 0) \
                    and isinstance(ca, int) and abs(ca) > 1:
                return V(NOVAL, tags)
            if isinstance(op, ast.Pow) and isinstance(ca, int) and isinstance(cb, int) and \
                    abs(ca).bit_length() * max(cb, 0) > 65536:
                return V(NOVAL, tags)
            fn = _BINOPS.get(type(op))
            if fn is not None:
                if isinstance(op, ast.Add) and isinstance(ca, (list, tuple)) and a.known and b.known:
                    items = list(a.c) + list(b.c)
                    return Val(tuple(items) if isinstance(a.c, tuple) else items, tags)
                return wrap(fn(ca, cb), tags, self.lim)
            return V(NOVAL, tags | {OPAQUE})
        if isinstance(op, ast.Add):
            ta, tb = text(a), text(b)
            if (ta is not None or tb is not None) and not (isinstance(ca, (int, float)) or isinstance(cb, (int, float))):
                p = (ta if ta is not None else PH) + (tb if tb is not None else PH)
                return V(NOVAL, tags | path_tags(p), partial=p[: self.lim["max_string"]])
            if a.known and isinstance(a.c, list) or b.known and isinstance(b.c, list):
                return V(NOVAL, tags)
        if isinstance(op, ast.Mod) and a.known and isinstance(a.c, str):
            return self.format_partial(a.c, b, "%")
        return V(NOVAL, tags)

    def format_partial(self, fmt: str, args: Val, how: str) -> Val:
        """'...%s...' % (known, unknown) -> a partial string with PH for the unknown parts."""
        if not _fmt_ok(fmt):
            return V(NOVAL, args.tags)
        items = self.iter_items(args) if args.known and isinstance(args.c, tuple) else [args]
        vals = [conc(x) if conc(x) is not NOVAL else (text(x) or PH) for x in items]
        try:
            p = fmt % tuple(vals) if how == "%" else fmt
        except (TypeError, ValueError):
            return V(NOVAL, T(*items))
        return V(NOVAL, T(*items) | path_tags(p), partial=p)

    def fstring(self, node, sc, ph) -> Val:
        parts, tags, known = [], set(), True
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
                continue
            if isinstance(v, ast.FormattedValue):
                x = self.ev(v.value, sc, ph)
                tags |= x.tags
                c = conc(x)
                spec = ""
                if v.format_spec is not None:
                    sv = self.fstring(v.format_spec, sc, ph)
                    spec = sv.c if sv.known else ""
                if c is NOVAL or x.ref or not _fmt_ok(spec):
                    known = False
                    parts.append(text(x) or PH)
                    continue
                try:
                    if v.conversion == ord("r"):
                        c = repr(c)
                    elif v.conversion == ord("s"):
                        c = str(c)
                    elif v.conversion == ord("a"):
                        c = ascii(c)
                    parts.append(format(c, spec))
                except (TypeError, ValueError):
                    known = False
                    parts.append(PH)
        s = "".join(parts)
        if len(s) > self.lim["max_string"]:
            return V(NOVAL, tags)
        if known:
            return Val(s, tags)
        return V(NOVAL, frozenset(tags) | path_tags(s), partial=s)

    def comp(self, node, sc, ph) -> Val:
        results, keys = [], []
        complete = [True]
        inner = Scope(sc, sc.self_val, sc.cls)
        inner.globs = set()

        def rec(i):
            if i == len(node.generators):
                if isinstance(node, ast.DictComp):
                    keys.append(self.ev(node.key, inner, ph))
                    results.append(self.ev(node.value, inner, ph))
                else:
                    results.append(self.ev(node.elt, inner, ph))
                return
            g = node.generators[i]
            it = self.ev(g.iter, inner, ph)
            items = self.iter_items(it)
            if items is None or self.iters + len(items) > self.lim["max_iter"]:
                complete[0] = False
                elem = self.element(it)
                if M(it, "environ") and g.ifs:      # variables picked by name: not the whole environment
                    elem = V(NOVAL, {SECRET_ENV})
                self.assign(g.target, elem, inner, ph)
                for cond in g.ifs:
                    self.ev(cond, inner, ph)
                rec(i + 1)
                return
            start = self.steps
            for n, item in enumerate(items):
                # long comprehensions are evaluated item by item only while each item is cheap (a char-code list
                # being decoded); a costly element over thousands of items is read once, abstractly
                if n == 64 and len(items) > 1024 and (self.steps - start) > 64 * 40:
                    complete[0] = False
                    break
                self.iters += 1
                self.tick()
                self.assign(g.target, item, inner, ph)
                keep = True
                for cond in g.ifs:
                    c = conc(self.ev(cond, inner, ph))
                    if c is NOVAL:
                        complete[0] = False
                    elif not c:
                        keep = False
                if keep:
                    rec(i + 1)

        rec(0)
        tags = T(*results) | T(*keys)
        if not complete[0]:
            out = V(NOVAL, tags)
            for r in results[:16]:
                out = merge(out, r)
            return V(NOVAL, tags, alts=M(out, "alts")) if M(out, "alts") else V(NOVAL, tags)
        if isinstance(node, ast.DictComp):
            d = {}
            for k, v in zip(keys, results):
                kc = conc(k)
                if kc is NOVAL or isinstance(kc, (list, dict)):
                    return V(NOVAL, tags)
                d[kc] = v
            return Val(d, tags)
        return Val(results, tags)

    # ----------------------------------------------------------------- calls
    def call(self, node, sc, ph) -> Val:
        fv = self.ev(node.func, sc, ph)
        args, kw = [], {}
        for a in node.args:
            if isinstance(a, ast.Starred):
                v = self.ev(a.value, sc, ph)
                items = self.iter_items(v)
                args.extend(items if items is not None else [self.element(v)])
            else:
                args.append(self.ev(a, sc, ph))
        for k in node.keywords:
            v = self.ev(k.value, sc, ph)
            if k.arg is None:
                if v.ref == "os.environ":
                    kw["**"] = V(NOVAL, {SECRET})
                elif v.known and isinstance(v.c, dict):
                    kw.update({str(x): y for x, y in v.c.items()})
                else:
                    kw["**"] = v
            else:
                kw[k.arg] = v
        hidden = bool(M(fv, "hidden"))
        if isinstance(node.func, ast.Name):
            seg = self.src(node.func)
            if seg and seg != node.func.id:
                hidden = True                                         # an identifier spelled with look-alike characters
        if isinstance(node.func, ast.Call) and fv.ref and fv.ref.startswith("builtins.") and \
                isinstance(node.func.func, ast.Name) and node.func.func.id in ("eval", "getattr"):
            hidden = True
        if hidden and canon(fv.ref) in DANGEROUS:
            self.emit("hidden_call", ph, node)
        return self.apply(fv, args, kw, sc, ph, node)

    def apply(self, fv: Val, args, kw, sc, ph, node) -> Val:
        ref = canon(fv.ref)
        fn = M(fv, "func")
        if fn is not None:
            bound = M(fv, "bound")
            return self.invoke(fn, args, kw, ph, bound)
        if ref == "#class":
            ci = M(fv, "cls")
            inst = V(ref="#inst", cls=ci)
            init = ci.scope.vars.get("__init__") if isinstance(ci, ClassInfo) else None
            if init is not None and M(init, "func") is not None:
                self.invoke(M(init, "func"), args, kw, ph, inst)
            return inst
        if ref == "#meth":
            return self.method(M(fv, "self"), M(fv, "name"), fv, args, kw, sc, ph, node)
        if ref == "#codefn":
            self.exec_code(M(fv, "code") or Val(), ph, node, sc)
            return Val()
        if ref is not None and ref[0] != "#":
            h = HANDLERS.get(ref)
            if h is None:
                last = ref.rsplit(".", 1)
                if len(last) == 2 and last[0] in HTTP_MODULES and last[1] in HTTP_VERBS:
                    h = Interp.h_http
            if h is not None:
                return h(self, ref, args, kw, sc, ph, node)
        return self.generic(fv, args, kw, ph)

    def generic(self, fv, args, kw, ph) -> Val:
        """An unknown callable: its result carries the taint of what went in (not the environment object itself).
        A local function handed to it is not run here (a registered command or route runs when called, not at import);
        the runners that do start it now (threads, atexit ...) have their own handler."""
        tags = set(fv.tags) - {OPAQUE}         # a method of an opaque object (re.compile(<long pattern>).match) is not
        for a in list(args) + list(kw.values()):
            if a.ref != "os.environ" and M(a, "func") is None:
                tags |= a.tags
        if args and all(a.known and conc(a) is not NOVAL for a in args) and any(_blob(a) for a in args) and (
                fv.ref != "#meth" or (M(fv, "self") is not None and M(fv, "self").known)):
            tags.add(OPAQUE)                       # a blob in, unknown out: a decoder the analysis could not follow
        return V(NOVAL, frozenset(tags) - {SOCK} if fv.ref != "#meth" else frozenset(tags))

    def invoke(self, fn: Func, args, kw, ph, self_val=None, force=False) -> Val:
        node = fn.node
        sh = self.sh
        limit = self.lim["max_depth"] if ph in AUTO else 2      # code that runs only when called: shallower
        passed = _arg_tags(list(args) + list(kw.values()))
        if sh.call_depth >= limit and not force:
            sh.entered.add(id(node))
            return V(NOVAL, passed)
        sig = (id(node), ph, tuple(_sig(a) for a in args), tuple(sorted((k, _sig(v)) for k, v in kw.items())),
               id(M(self_val, "cls")) if self_val is not None else None)
        if sig in sh.cache:
            return sh.cache[sig]
        sh.cache[sig] = V(NOVAL, passed)                   # while it runs (recursion): what went in
        sh.entered.add(id(node))
        interp = fn.interp
        scope = Scope(fn.scope, self_val, fn.cls)
        scope.vars["#returns"] = []
        a = node.args
        params = [p.arg for p in a.posonlyargs + a.args]
        given = list(args)
        if self_val is not None and params:
            scope.vars[params[0]] = self_val
            params = params[1:]
        defaults = list(a.defaults)
        nd = len(defaults)
        allp = a.posonlyargs + a.args
        for i, p in enumerate(params):
            if i < len(given):
                scope.vars[p] = given[i]
            elif p in kw:
                scope.vars[p] = kw[p]
            else:
                j = len(allp) - nd
                idx = allp.index(next(x for x in allp if x.arg == p))
                if idx >= j and nd:
                    scope.vars[p] = interp.ev(defaults[idx - j], fn.scope, ph)
                else:
                    scope.vars[p] = kw.get("**", Val())
        if a.vararg:
            rest = given[len(params):]
            scope.vars[a.vararg.arg] = Val(tuple(rest), T(*rest))
        for i, p in enumerate(a.kwonlyargs):
            if p.arg in kw:
                scope.vars[p.arg] = kw[p.arg]
            elif a.kw_defaults[i] is not None:
                scope.vars[p.arg] = interp.ev(a.kw_defaults[i], fn.scope, ph)
            else:
                scope.vars[p.arg] = Val()
        if a.kwarg:
            extra = {k: v for k, v in kw.items() if k not in params}
            scope.vars[a.kwarg.arg] = Val(extra, T(*extra.values()))
        sh.call_depth += 1
        try:
            if isinstance(node, ast.Lambda):
                ret = interp.ev(node.body, scope, ph)
            else:
                ret = None
                try:
                    interp.block(node.body, scope, ph, definite=True)
                except _Return as r:
                    ret = r.val
                except (_Break, _Continue):
                    pass
                for r in scope.vars.get("#returns", []):
                    ret = r if ret is None else merge(ret, r)
                if ret is None:
                    ret = Val(None)
                if _is_generator(node) and not (ret.known and isinstance(ret.c, list)):
                    ret = V(NOVAL, ret.tags)
        finally:
            sh.call_depth -= 1
        sh.cache[sig] = ret
        return ret

    # ----------------------------------------------------------------- methods of values
    def method(self, obj: Val | None, name: str, fv: Val, args, kw, sc, ph, node) -> Val:
        if obj is None:
            return self.generic(fv, args, kw, ph)
        if obj.ref == "os.environ":
            if name in ("get", "setdefault", "pop", "__getitem__"):
                return self.env_get(args[0] if args else Val(), args[1] if len(args) > 1 else None)
            if name == "copy":
                return obj
            if name in ("items", "keys", "values", "__iter__", "__repr__", "__str__"):
                return V(NOVAL, {SECRET}, environ=True)
            return Val()
        if obj.ref == "#file":
            return self.file_method(obj, name, args, kw, ph, node)
        if obj.ref == "#loader":
            pv = M(obj, "path") or Val()
            code = V(NOVAL, self.open_file(pv, "r", ph, node).tags, fromfile=pv)
            if name in ("load_module", "exec_module"):
                self.exec_code(code, ph, node, sc)
                return Val()
            return code if name in ("get_code", "get_source", "get_data") else Val()
        if obj.ref == "#sock":
            return self.sock_method(obj, name, args, kw, ph, node)
        if obj.ref == "#http":
            if name in HTTP_VERBS:
                return self.h_http(f"{M(obj, 'mod') or 'requests'}.{name}", args, kw, sc, ph, node, base=M(obj, "base"))
            return V(NOVAL, obj.tags)
        if obj.ref == "#httpconn":
            if name in ("request", "putrequest", "send"):
                host = M(obj, "host") or Val()
                path = args[1] if len(args) > 1 else kw.get("url", Val(""))
                target = (text(host) or PH) + (text(path) or "")
                self.send(V(target) if PH not in target else V(NOVAL, partial=target), [*args, *kw.values()], ph, node)
                return Val()
            if name in ("getresponse",):
                return V(NOVAL, {NET})
            return V(NOVAL, obj.tags)
        if obj.ref == "#smtp":
            if name in ("sendmail", "send_message"):
                self.send(M(obj, "host") or Val(), [*args, *kw.values()], ph, node)
            return Val()
        if obj.ref == "#request":
            if name in ("add_header", "add_unredirected_header"):
                obj.meta["payload"] = list(obj.meta.get("payload", [])) + list(args)
            return Val()
        if obj.ref == "#path":
            return self.path_method(obj, name, args, kw, sc, ph, node)
        if obj.ref == "#opener" and name == "open":
            return self.h_urlopen("urllib.request.urlopen", args, kw, sc, ph, node)
        if obj.ref == "#zip":
            if name in ("write",) and args:
                for t in texts(args[0]):
                    if path_class(t) == "credential":
                        self.taint_path(M(obj, "path"), {SECRET})
                if CRED_PATH in args[0].tags:
                    self.taint_path(M(obj, "path"), {SECRET})
            if name in ("writestr",) and len(args) > 1:
                self.taint_path(M(obj, "path"), args[1].tags & {SECRET, SECRET_ENV, SYSINFO})
            return Val()
        if obj.ref == "#proc":
            if name in ("communicate", "read") or name.startswith("read"):
                return V(NOVAL, obj.tags)
            if name == "stdin" or name == "write":
                return Val()
            return V(NOVAL, obj.tags)
        # methods of known strings / bytes / containers
        if obj.known:
            r = self.value_method(obj, name, args, kw, ph)
            if r is not None:
                return r
        partial = M(obj, "partial")
        if partial is not None and name in ("format", "join", "strip", "rstrip", "lstrip", "encode", "decode", "replace"):
            return self.partial_method(obj, partial, name, args, kw)
        if name in ("decode",) and DECODED not in obj.tags and args and any(
                str(conc(a)).replace("-", "_").lower() in DECODE_CODECS for a in args[:1]):
            return V(NOVAL, obj.tags | {DECODED})
        if name in ("read", "readline", "readlines", "recv", "json", "text", "content", "iter_content", "iter_lines",
                    "getvalue", "fetchall", "fetchone"):
            return V(NOVAL, obj.tags - {SOCK})
        alts = M(obj, "alts")
        if alts:
            out = None
            for a in alts[:8]:
                r = self.method(a, name, V(ref="#meth", self=a, name=name), args, kw, sc, ph, node)
                out = r if out is None else merge(out, r)
            if out is not None:
                return out
        src = M(obj, "src")
        if name in ("start", "run") and src is not None:
            pass
        out = self.generic(V(NOVAL, obj.tags, "#meth"), args, kw, ph)
        if name == "fileno" and SOCK in obj.tags:
            return V(NOVAL, {SOCK})
        return out

    def value_method(self, obj: Val, name: str, args, kw, ph) -> Val | None:
        c = obj.c
        cargs = [conc(a) for a in args]
        ckw = {k: conc(v) for k, v in kw.items()}
        tags = obj.tags | T(*args, *kw.values())
        if isinstance(c, list):
            if name == "append" and args:
                c.append(args[0])
                obj.tags = obj.tags | args[0].tags
                return Val(None)
            if name == "extend" and args:
                items = self.iter_items(args[0])
                if items is not None:
                    c.extend(items)
                obj.tags = obj.tags | args[0].tags
                return Val(None)
            if name == "insert" and len(args) == 2 and isinstance(cargs[0], int):
                c.insert(cargs[0], args[1])
                obj.tags = obj.tags | args[1].tags
                return Val(None)
            if name == "reverse":
                c.reverse()
                return Val(None)
            if name == "pop":
                try:
                    return c.pop(cargs[0] if args else -1)
                except (IndexError, TypeError):
                    return V(NOVAL, obj.tags)
            if name == "copy":
                return Val(list(c), obj.tags)
            if name == "index" and args:
                pc = conc(obj)
                try:
                    return Val(pc.index(cargs[0])) if pc is not NOVAL else Val()
                except ValueError:
                    return Val()
            return None
        if isinstance(c, dict):
            if name == "get" and args:
                k = cargs[0]
                if k is NOVAL:
                    return V(NOVAL, obj.tags)
                if k in c:
                    return c[k]
                return args[1] if len(args) > 1 else Val(None)
            if name == "items":
                return Val([Val((V(k, obj.tags), v), obj.tags | v.tags) for k, v in c.items()], obj.tags)
            if name == "keys":
                return Val([V(k) for k in c], obj.tags)
            if name == "values":
                return Val(list(c.values()), obj.tags)
            if name == "update" and args and args[0].known and isinstance(args[0].c, dict):
                c.update(args[0].c)
                obj.tags = obj.tags | args[0].tags
                return Val(None)
            if name == "update":
                c.update({k: v for k, v in kw.items()})
                obj.tags = obj.tags | T(*args, *kw.values())
                return Val(None)
            if name == "setdefault" and args and cargs[0] is not NOVAL:
                return c.setdefault(cargs[0], args[1] if len(args) > 1 else Val(None))
            if name == "pop" and args and cargs[0] is not NOVAL:
                return c.pop(cargs[0], args[1] if len(args) > 1 else Val(None))
            if name == "copy":
                return Val(dict(c), obj.tags)
            return None
        if isinstance(c, (str, bytes)) and name in SAFE_STR:
            if any(x is NOVAL for x in cargs) or any(x is NOVAL for x in ckw.values()):
                if name in ("join",) and args:
                    items = self.iter_items(args[0])
                    if items is not None:
                        sep = c
                        p = sep.join(text(i) or PH for i in items) if isinstance(sep, str) else None
                        if p is not None:
                            return V(NOVAL, tags | path_tags(p), partial=p)
                    return V(NOVAL, tags)
                if name == "format" and isinstance(c, str) and _fmt_ok(c):
                    vals = [conc(a) if conc(a) is not NOVAL else (text(a) or PH) for a in args]
                    kvals = {k: (conc(v) if conc(v) is not NOVAL else (text(v) or PH)) for k, v in kw.items()}
                    try:
                        p = c.format(*vals, **kvals)
                        return V(NOVAL, tags | path_tags(p), partial=p)
                    except (IndexError, KeyError, ValueError, TypeError, AttributeError):
                        return V(NOVAL, tags)
                if name == "replace" and isinstance(c, str):
                    return V(NOVAL, tags, partial=c)
                return V(NOVAL, tags)
            if name in ("encode", "decode"):
                codec = str(cargs[0] if cargs else ckw.get("encoding", "utf-8")).lower()
                if codec.replace("_", "-") not in {x.replace("_", "-") for x in TEXT_CODECS}:
                    if codec.replace("-", "_") in DECODE_CODECS and isinstance(c, (str, bytes)):
                        try:
                            r = codecs.decode(c, codec)
                            return wrap(r, tags | {DECODED}, self.lim)
                        except Exception:
                            return V(NOVAL, tags | {DECODED})
                    return V(NOVAL, tags)
            if name in ("center", "ljust", "rjust", "zfill") and cargs and isinstance(cargs[0], int) and \
                    cargs[0] > self.lim["max_string"]:
                return V(NOVAL, tags)
            if name == "expandtabs" and cargs and isinstance(cargs[0], int) and cargs[0] > 64:
                return V(NOVAL, tags)
            if name in ("format", "format_map") and isinstance(c, str) and not _fmt_ok(c):
                return V(NOVAL, tags)
            if name == "replace" and len(cargs) >= 2:
                old, new = cargs[0], cargs[1]
                try:
                    grow = (c.count(old) if old else len(c) + 1) * max(len(new) - len(old), 0)
                except TypeError:
                    return V(NOVAL, tags)
                if len(c) + grow > self.lim["max_string"]:
                    return V(NOVAL, tags)
            if name == "join" and cargs:
                seq = cargs[0]
                try:
                    total = sum(len(x) for x in seq) + len(c) * max(len(seq) - 1, 0)
                except TypeError:
                    return V(NOVAL, tags)
                if total > self.lim["max_string"]:
                    return V(NOVAL, tags)
                items = self.iter_items(args[0]) or []
                tags = tags | T(*items)
            try:
                fn = getattr(type(c), name) if name in ("maketrans", "fromhex") else getattr(c, name)
                r = fn(*cargs, **ckw)
            except Exception:
                return V(NOVAL, tags)
            if name == "fromhex":
                tags = tags | {DECODED}
            return wrap(r, tags, self.lim)
        return None

    def partial_method(self, obj, partial, name, args, kw) -> Val:
        tags = obj.tags | T(*args, *kw.values())
        if name == "format":
            vals = [conc(a) if conc(a) is not NOVAL else (text(a) or PH) for a in args]
            try:
                p = partial.format(*vals, **{k: conc(v) if conc(v) is not NOVAL else PH for k, v in kw.items()})
            except Exception:
                p = partial
            return V(NOVAL, tags | path_tags(p), partial=p)
        if name == "join" and args:
            items = self.iter_items(args[0])
            if items is not None:
                p = partial.join(text(i) or PH for i in items)
                return V(NOVAL, tags | path_tags(p), partial=p)
        if name == "replace" and len(args) >= 2 and all(isinstance(conc(a), str) for a in args[:2]):
            p = partial.replace(conc(args[0]), conc(args[1]))
            return V(NOVAL, tags | path_tags(p), partial=p)
        if name in ("strip", "rstrip", "lstrip") and not args:
            return V(NOVAL, tags, partial=getattr(partial, name)())
        return V(NOVAL, tags, partial=partial)

    # ----------------------------------------------------------------- files
    def open_file(self, pv: Val, mode: str, ph, node) -> Val:
        write = any(m in mode for m in "wax+")
        read_tags = set()
        for t in texts(pv) or []:
            cls = path_class(t)
            if cls == "credential":
                # a project's .env holds environment variables: secret only on the way to a suspicious address
                read_tags.add(SECRET_ENV if t.replace("\\", "/").rsplit("/", 1)[-1] == ".env" else SECRET)
            elif cls == "local" and PH not in t.split("/")[0]:
                read_tags.add(LOCAL)
            if self.ctx.was_downloaded(t):
                read_tags.add(NET)
            read_tags |= self.sh.file_tags.get(self.ctx._norm(t), set())
        if CRED_PATH in pv.tags:
            read_tags.add(SECRET)
        if NET_FILE in pv.tags:
            read_tags.add(NET)
        if not read_tags:
            read_tags.add(FILE)
        meta = {"path": pv, "mode": mode, "written": frozenset()}
        return Val(NOVAL, frozenset(read_tags) if not write or "+" in mode else frozenset(), "#file", meta)

    def taint_path(self, pv, tags):
        if pv is None or not tags:
            return
        for t in texts(pv):
            if PH not in t:
                key = self.ctx._norm(t)
                self.sh.file_tags[key] = self.sh.file_tags.get(key, set()) | set(tags)
                if NET in tags:
                    self.ctx.add_downloaded(t)

    def write_file(self, pv: Val, data: Val, ph, node, fobj: Val | None = None):
        """Data written to a path: an autostart place is persistence; fetched data makes it a downloaded file."""
        tset = texts(pv)
        auto = AUTOSTART_PATH in pv.tags or any(path_class(t) == "autostart" for t in tset)
        dtext = text(data) or ""
        if not auto:
            for t in tset:
                base = t.replace("\\", "/").rsplit("/", 1)[-1].lower()
                if base in ("sitecustomize.py", "usercustomize.py") and not t.startswith(PH):
                    auto = True
                if base.endswith(".pth") and re.search(r"^import\s", dtext, re.M):
                    auto = True
        if auto:
            self.emit("persistence", ph, node)
        if NET in data.tags or NET_FILE in data.tags:
            self.taint_path(pv, {NET})
            if fobj is not None:
                fobj.meta["written"] = fobj.meta.get("written", frozenset()) | {NET}
        keep = data.tags & {SECRET, SECRET_ENV, SYSINFO, DECODED}
        if keep:
            self.taint_path(pv, keep)
            if fobj is not None:
                fobj.meta["written"] = fobj.meta.get("written", frozenset()) | keep

    def file_method(self, obj, name, args, kw, ph, node) -> Val:
        if name in ("write", "writelines") and args:
            self.write_file(M(obj, "path") or Val(), args[0], ph, node, obj)
            return Val()
        if name in ("read", "readline", "readlines", "__iter__", "__next__", "__enter__"):
            # the text keeps the path it was read from: exec() of it runs that file (Interp.exec_code)
            return obj if name == "__enter__" else V(NOVAL, obj.tags, fromfile=M(obj, "path"))
        return V(NOVAL, obj.tags) if name in ("fileno",) else Val()

    def path_method(self, obj, name, args, kw, sc, ph, node) -> Val:
        p = text(obj) or PH
        if name in ("joinpath", "__truediv__"):
            out = obj
            for a in args:
                out = self.binop(ast.Div(), out, a)
            return out
        if name in ("expanduser", "resolve", "absolute", "with_name", "with_suffix"):
            if name == "with_name" and args and isinstance(conc(args[0]), str):
                return self.mkpath(p.rsplit("/", 1)[0] + "/" + conc(args[0]) if "/" in p else conc(args[0]), obj)
            if name == "with_suffix" and args and isinstance(conc(args[0]), str):
                return self.mkpath(p.rsplit(".", 1)[0] + conc(args[0]), obj)
            return obj
        if name in ("read_text", "read_bytes"):
            return V(NOVAL, self.open_file(obj, "r", ph, node).tags, fromfile=obj)
        if name in ("write_text", "write_bytes") and args:
            self.write_file(obj, args[0], ph, node)
            return Val()
        if name == "open":
            mode = conc(args[0]) if args else conc(kw.get("mode", Val("r")))
            return self.open_file(obj, mode if isinstance(mode, str) else "r", ph, node)
        if name in ("glob", "rglob", "iterdir"):
            return V(NOVAL, obj.tags | path_tags(p + "/x"), partial=p + "/" + PH)
        if name == "chmod":
            self.ctx.mark_executable(p)
            return Val()
        return Val()

    # ----------------------------------------------------------------- network
    def sock_method(self, obj, name, args, kw, ph, node) -> Val:
        if name in ("connect", "connect_ex") and args:
            addr = args[0]
            host = addr.c[0] if addr.known and isinstance(addr.c, (list, tuple)) and addr.c else addr
            obj.meta["host"] = host
            return Val()
        if name in ("send", "sendall", "sendto", "sendfile", "write") and args:
            target = obj.meta.get("host") or Val()
            if name == "sendto" and len(args) > 1:
                a = args[1]
                target = a.c[0] if a.known and isinstance(a.c, (list, tuple)) and a.c else a
            self.send(target, args[:1], ph, node)
            return Val()
        if name in ("recv", "recvfrom", "recv_into", "makefile", "read"):
            return V(NOVAL, {NET, SOCK} if name == "makefile" else {NET})
        if name == "fileno":
            return V(NOVAL, {SOCK})
        return Val(NOVAL, obj.tags)

    def send(self, target: Val, payload, ph, node):
        """Data leaving over the network to `target`: secrets anywhere, secret env vars / user and host information to
        suspicious addresses, user and host information at install / import."""
        tags = set(target.tags)
        for p in payload:
            if isinstance(p, Val) and p.ref != "os.environ":
                tags |= p.tags
                if p.known and isinstance(p.c, (list, tuple, dict)):
                    tags |= _deep_tags(p)
            elif isinstance(p, Val):
                tags.add(SECRET)
        cls = None
        for t in texts(target):
            cls = cls or endpoint_class(t)
        if SECRET in tags:
            self.emit("secret_exfil", ph, node)
        elif SECRET_ENV in tags and cls:
            self.emit("secret_exfil", ph, node)
        if SYSINFO in tags:
            self.emit("suspicious_send" if cls else "sysinfo_beacon", ph, node)
        elif cls in ("collector", "messenger") and ph in AUTO and SECRET not in tags:
            self.emit("suspicious_send", ph, node)

    def h_http(self, ref, args, kw, sc, ph, node, base=None) -> Val:
        verb = ref.rsplit(".", 1)[-1]
        url = kw.get("url") or (args[1] if verb == "request" and len(args) > 1 else args[0] if args else Val())
        if base is not None and not (text(url) or "").startswith("http"):
            url = self.binop(ast.Add(), base, url)
        if ref.split(".")[0] in ("requests", "httpx", "urllib3", "aiohttp") and verb in ("Session", "session", "Client",
                                                                                         "AsyncClient", "PoolManager",
                                                                                         "ClientSession"):
            return V(ref="#http", mod=ref.split(".")[0], base=kw.get("base_url"))
        payload = [url] + [v for k, v in kw.items() if k in ("data", "json", "params", "headers", "files", "body",
                                                               "fields", "content", "cookies", "auth", "**")]
        payload += [a for a in args[1:] if a is not url]
        self.send(url, payload, ph, node)
        tags = {NET}
        if any(IP_LOOKUP.search(t) for t in texts(url)):
            tags.add(SYSINFO)
        return V(NOVAL, tags)

    def h_urlopen(self, ref, args, kw, sc, ph, node) -> Val:
        req = args[0] if args else kw.get("url", Val())
        if req.ref == "#request":
            url = M(req, "url") or Val()
            payload = [url] + list(M(req, "payload", []))
        else:
            url = req
            payload = [url]
        payload += list(args[1:2]) + [kw[k] for k in ("data",) if k in kw]
        self.send(url, payload, ph, node)
        tags = {NET}
        if any(IP_LOOKUP.search(t) for t in texts(url)):
            tags.add(SYSINFO)
        return V(NOVAL, tags)

    # ----------------------------------------------------------------- code and process sinks
    def exec_code(self, code: Val, ph, node, sc, kind="exec") -> Val:
        """Code run as Python: rebuilt -> analyzed again; else judged by where it came from."""
        if M(code, "codeobj") is not None:
            code = M(code, "codeobj")
        if not code.known and M(code, "fromfile") is not None and \
                self.run_package_file(M(code, "fromfile"), ph, node, "python"):
            return V(NOVAL, code.tags)                   # the text of a package file: that file was read at this phase
        known = [c for c in cands(code) if isinstance(c.s(), str)]
        for c in known[:4]:
            src = c.s()
            if kind == "eval":
                try:
                    tree = ast.parse(src.strip(), mode="eval")
                except (SyntaxError, ValueError, MemoryError, RecursionError):
                    tree = None
                if tree is not None and len(known) == 1 and self.depth < self.lim["max_depth"]:
                    sub = Interp(self.ctx, self.file, ph, self.depth + 1, self.line(node), src)
                    sub.glob = sc
                    sub.sh.call_depth += 1
                    try:
                        r = sub.ev(tree.body, sc, ph)
                    finally:
                        sub.sh.call_depth -= 1
                    if r.ref:
                        r = Val(r.c, r.tags, r.ref, dict(r.meta or {}, hidden=True))
                    return r
            self.ctx.nested_python(src, ph, self.file, self.line(node), self.depth + 1, env=sc.module().vars)
        if known and code.known:
            return Val()
        partial = M(code, "partial")
        read = False
        if partial and self.depth < self.lim["max_depth"]:
            try:
                ast.parse(partial.strip(), mode="eval" if kind == "eval" else "exec")
                read = True
            except (SyntaxError, ValueError, MemoryError, RecursionError):
                pass
            if read:
                # generated code whose unknown parts are names / values: its structure was read
                self.ctx.nested_python(partial, ph, self.file, self.line(node), self.depth + 1, env=sc.module().vars)
        self.judge_unknown_exec(code, ph, node, program_known=read)
        return V(NOVAL, code.tags)

    def judge_unknown_exec(self, v: Val, ph, node, program_known=False):
        tags = v.tags
        if NET in tags or NET_FILE in tags:
            self.emit("download_exec", ph, node)
        elif DECODED in tags:
            self.emit("decode_exec", ph, node)
        elif (OPAQUE in tags or ENV in tags and ph in ("install", "interpreter_start")) and \
                not (tags & SOURCE_TAGS) and not program_known and ph in AUTO:
            # unknown because it is data (a parameter, a table entry) is not "unreadable"; computed from constants by
            # code the analysis could not follow is; so is code from an environment variable at install / startup
            # (at import, eval(os.getenv("X_DEBUG", "False")) is a configuration idiom)
            self.emit("unreadable_exec", ph, node)

    def run_process(self, argv_or_cmd: Val, ph, node, shell=None, kw=None, ref="") -> Val:
        """A process started by the code: the rebuilt command line goes to shell.py; unknown parts are judged by tags."""
        kw = kw or {}
        for k in ("stdin", "stdout", "stderr"):
            if k in kw and SOCK in kw[k].tags:
                self.emit("remote_shell", ph, node)
        v = argv_or_cmd
        if not v.known:                          # an argument list built in branches: read its known form
            lst = next((a for a in M(v, "alts", ()) if a.known and isinstance(a.c, (list, tuple))), None)
            if lst is not None:
                v = Val(lst.c, lst.tags | v.tags, None, lst.meta)
        cmd = None
        program = None
        prog_val = None
        if v.known and isinstance(v.c, (list, tuple)):
            parts = [text(x) if text(x) is not None else PH for x in v.c]
            if v.c:
                prog_val = v.c[0]
            cmd = " ".join(shlex.quote(p) if p != PH else PH for p in parts)
            program = parts[0] if parts else None
            if parts and PH not in parts[0]:
                if len(parts) > 1 and parts[0].rsplit("/", 1)[-1] in self.ctx.pol.interpreters and v.c[1].tags & {NET_FILE}:
                    self.emit("download_exec", ph, node)
        else:
            t = text(v)
            if t is None and M(v, "alts"):
                t = texts(v)[0] if texts(v) else None
            cmd = t
            prog_val = v
            if t is not None:
                program = t.split()[0] if t.split() else None
        info = {"programs": [], "sysinfo": False, "network": False}
        if program and PH in program and PH not in program.replace("\\", "/").rsplit("/", 1)[-1]:
            program = program.replace("\\", "/").rsplit("/", 1)[-1]          # unknown folder, known program
        if cmd is not None and program and PH not in program:
            for alt in (texts(v) if not (v.known and isinstance(v.c, (list, tuple))) else [cmd])[:4] or [cmd]:
                info = self.ctx.shell(alt, ph, self.file, self.line(node), self.depth)
            prog = program.replace("\\", "/").rsplit("/", 1)[-1].lower()
            if ph in ("install", "interpreter_start") and prog not in self.ctx.pol.build and \
                    not (prog.startswith("python") and len(prog) < 12):
                self.emit("install_process", ph, node)
            if NET_FILE in (prog_val.tags if prog_val is not None else ()):
                self.emit("download_exec", ph, node)
        else:
            pv = prog_val if prog_val is not None else v
            if v.known and isinstance(v.c, (list, tuple)):
                pv = Val(NOVAL, pv.tags - {OPAQUE, ENV})   # a program with an argument list is not code text
            self.judge_unknown_exec(pv, ph, node)
        if ph in ("install", "interpreter_start") and cmd is not None:
            self.runs_package_files(v, cmd, ph, node, kw)
        tags = set()
        if info.get("sysinfo"):
            tags.add(SYSINFO)
        if info.get("network"):
            tags.add(NET)
        for t in texts(v) + ([text(x) for x in v.c if text(x)] if v.known and isinstance(v.c, (list, tuple)) else []):
            if any(path_class(tok) == "credential" for tok in re.split(r"[\s'\"]+", t or "") if tok):
                tags.add(SECRET)
        return V(NOVAL, tags, "#proc")

    # ----------------------------------------------------------------- package files the code hands work to
    def find_package_file(self, t: str, cwd: str = "") -> tuple[str, str | None, object]:
        """(status, rel, path) of a path the code names: "file" / "aside" (shipped, readable), "left" (shipped, too large
        to keep), "absent" (relative, not shipped), "outside" (absolute), "unknown" (leading folders unknown, no match).
        Relative paths are taken from the working directory (the package root while pip builds it) or this file's folder."""
        t = t.replace("\\", "/")
        if PH in t:
            tail = t.split(PH)[-1]
            hits = self.ctx.bundled_tail(tail) if tail.strip("/") and "/" in "/" + tail.lstrip("/") else []
            return ("file", hits[0][0], hits[0][1]) if len(hits) == 1 else ("unknown", None, None)
        if t.startswith(("/", "~")) or re.match(r"^[A-Za-z]:/", t):
            return "outside", None, None
        here = self.file.rsplit("/", 1)[0] if "/" in self.file else ""
        bases = [cwd] + ([here] if here and here != cwd else [])
        status = "absent"
        for base in bases:
            from . import norm_rel
            rel = norm_rel(f"{base}/{t}" if base else t)
            st, path = self.ctx.bundled(rel)
            if st in ("file", "aside"):
                return st, rel, path
            if st == "left":
                status = "left"
        return status, None, None

    def run_package_file(self, pv: Val, ph, node, lang: str, cwd: str = "") -> bool:
        """A package file this code runs (exec of its text, runpy, a loader, a script it starts), read at this phase.
        At install / interpreter start one the package ships but that could not be read (too large to keep or to read)
        is a finding. A file the package does not ship is not: running it fails, or code that was read makes it first.
        True when the path was found."""
        if ph not in AUTO:
            return False
        handled = False
        for t in texts(pv)[:4]:
            status, rel, path = self.find_package_file(t, cwd)
            if status in ("file", "aside"):
                handled = True
                if not self.ctx.run_file(rel, path, lang, ph) and ph in ("install", "interpreter_start"):
                    self.emit("install_runs_unread", ph, node, f"{t}: too large to read")
            elif status == "left":
                handled = True
                if ph in ("install", "interpreter_start"):
                    self.emit("install_runs_unread", ph, node, f"{t}: too large to read")
        return handled

    def runs_package_files(self, v: Val, cmd: str, ph, node, kw):
        """A command run at install that hands the work to files of the package: a script given to an interpreter, a
        Makefile for make, CMake files for cmake, a configure script. They are read at install (make and CMake files
        for the commands they run); one that cannot be read is a finding (see run_package_file)."""
        from .shell import _argv, _split_commands
        cwd = text(kw["cwd"]) if "cwd" in kw and text(kw["cwd"]) else ""
        if PH in cwd or cwd.startswith(("/", "~")):
            cwd = ""
        if v.known and isinstance(v.c, (list, tuple)):
            argvs = [[text(x) if text(x) is not None else PH for x in v.c]]
        else:
            argvs = [_argv(c) for pipe in _split_commands(cmd) for c in pipe][:8]
        for argv in argvs:
            if not argv or PH in argv[0].rsplit("/", 1)[-1]:
                continue
            prog = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
            args = argv[1:]
            if prog.startswith("python") and len(prog) < 12 or prog in ("py", "sys.executable"):
                if "-c" in args:
                    continue
                if "-m" in args and args.index("-m") + 1 < len(args):
                    name = args[args.index("-m") + 1]
                    if self.local_module(name):
                        self.load_module(name, ph)
                    continue
                script = next((a for a in args if not a.startswith("-")), None)
                if script:
                    self.run_package_file(Val(script), ph, node, "python", cwd)
            elif prog in ("sh", "bash", "zsh", "dash", "ksh"):
                script = next((a for a in args if not a.startswith("-")), None)
                if script and "-c" not in args:
                    self.run_package_file(Val(script), ph, node, "shell", cwd)
            elif prog in ("make", "gmake"):
                d = cwd
                if "-C" in args and args.index("-C") + 1 < len(args):
                    d = "/".join(x for x in (cwd, args[args.index("-C") + 1]) if x)
                names = [args[args.index(f) + 1] for f in ("-f", "--file") if f in args and args.index(f) + 1 < len(args)]
                for name in names or ["GNUmakefile", "makefile", "Makefile", "Makefile.in"]:
                    if self.run_package_file(Val(name), ph, node, "make", d):
                        break
            elif prog == "cmake":
                if "--build" in args or "--install" in args or "-E" in args:
                    continue
                cm = [(rel, p) for rel, p in list(self.ctx.by_rel.items()) + list(self.ctx._side().items())
                      if rel.rsplit("/", 1)[-1] == "CMakeLists.txt" or rel.endswith(".cmake")][:50]
                for rel, p in cm:
                    if not self.ctx.run_file(rel, p, "cmake", ph):
                        self.emit("install_runs_unread", ph, node, f"{rel}: too large to read")
                for rel in sorted(self.ctx._left):
                    if rel.rsplit("/", 1)[-1] == "CMakeLists.txt" or rel.endswith(".cmake"):
                        self.emit("install_runs_unread", ph, node, f"{rel}: too large to read")
            elif prog == "configure" or "/" in argv[0] and not argv[0].startswith(("/", "~")):
                self.run_package_file(Val(argv[0]), ph, node, "shell", cwd)


def _blob(v: Val) -> bool:
    """A constant big enough to hide code in (a name like "_strptime" is not)."""
    c = v.c if v.known else None
    return isinstance(c, (str, bytes)) and len(c) >= 24 or isinstance(c, (list, tuple)) and len(c) >= 16


def _arg_tags(vals) -> frozenset:
    """Taint of call arguments; the environment object handed on (env=os.environ) is not data yet."""
    return frozenset().union(*[v.tags for v in vals if isinstance(v, Val) and v.ref != "os.environ"])


_GENERATORS: dict = {}


def _is_generator(node) -> bool:
    key = id(node)
    g = _GENERATORS.get(key)
    if g is None:
        stack, g = list(node.body), False
        while stack and not g:
            n = stack.pop()
            if isinstance(n, (ast.Yield, ast.YieldFrom)):
                g = True
            elif not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                stack.extend(ast.iter_child_nodes(n))
        if len(_GENERATORS) > 200000:
            _GENERATORS.clear()
        _GENERATORS[key] = g
    return g


def _deep_tags(v: Val, depth=0) -> set:
    out = set(v.tags)
    if depth > 6 or not v.known:
        return out
    c = v.c
    items = c.values() if isinstance(c, dict) else c if isinstance(c, (list, tuple)) else ()
    for x in items:
        if isinstance(x, Val):
            if x.ref == "os.environ":
                out.add(SECRET)
            out |= _deep_tags(x, depth + 1)
    return out


def _sig(v: Val):
    c = conc(v) if v.known else NOVAL
    if c is not NOVAL and isinstance(c, (str, bytes)):
        c = c[:64]
    elif c is not NOVAL and not isinstance(c, (int, float, bool, type(None))):
        c = "#"
    return (c if c is not NOVAL else "?", tuple(sorted(v.tags)), v.ref, M(v, "partial", "")[:64] if M(v, "partial") else "")


def _compare(op, a, b) -> bool:
    import operator
    table = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le,
             ast.Gt: operator.gt, ast.GtE: operator.ge, ast.Is: lambda x, y: x is y or x == y and x is None,
             ast.IsNot: lambda x, y: not (x is y or x == y and x is None),
             ast.In: lambda x, y: x in y, ast.NotIn: lambda x, y: x not in y}
    return table[type(op)](a, b)


_BINOPS = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b,
           ast.FloorDiv: lambda a, b: a // b, ast.Div: lambda a, b: a / b, ast.Mod: lambda a, b: a % b,
           ast.Pow: lambda a, b: a ** b, ast.LShift: lambda a, b: a << b, ast.RShift: lambda a, b: a >> b,
           ast.BitXor: lambda a, b: a ^ b, ast.BitAnd: lambda a, b: a & b, ast.BitOr: lambda a, b: a | b}


# --------------------------------------------------------------------------------------------------------- handlers

def _h(*names):
    def deco(fn):
        for n in names:
            HANDLERS[n] = fn
        return fn
    return deco


HANDLERS: dict = {}


def _arg(args, kw, i, name, default=None):
    if len(args) > i:
        return args[i]
    if name in kw:
        return kw[name]
    return default if default is not None else Val()


@_h("builtins.exec", "builtins.execfile", "builtins.eval")
def _h_exec(self, ref, args, kw, sc, ph, node):
    code = _arg(args, kw, 0, "source")
    if ref == "builtins.execfile":
        return self.exec_code(V(NOVAL, self.open_file(code, "r", ph, node).tags), ph, node, sc)
    return self.exec_code(code, ph, node, sc, "eval" if ref == "builtins.eval" else "exec")


@_h("builtins.compile")
def _h_compile(self, ref, args, kw, sc, ph, node):
    code = _arg(args, kw, 0, "source")
    mode = conc(_arg(args, kw, 2, "mode"))
    return Val(code.c, code.tags, None, dict(code.meta or {}, compiled=mode or "exec"))


@_h("types.FunctionType", "types.CodeType", "types.LambdaType")
def _h_functype(self, ref, args, kw, sc, ph, node):
    return V(NOVAL, T(*args), "#codefn", code=args[0] if args else Val())


@_h("marshal.loads", "pickle.loads", "dill.loads", "cloudpickle.loads", "pickle.load", "marshal.load")
def _h_unmarshal(self, ref, args, kw, sc, ph, node):
    data = args[0] if args else Val()
    if ref.startswith(("pickle", "dill", "cloudpickle")):
        if NET in data.tags:
            self.emit("download_exec", ph, node)
        elif DECODED in data.tags:
            self.emit("decode_exec", ph, node)
        return V(NOVAL, data.tags)
    dec = {DECODED} if const_origin(data) else set()
    return V(NOVAL, data.tags | dec, None, codeobj=V(NOVAL, data.tags | dec))


@_h("runpy.run_path", "runpy.run_module")
def _h_runpy(self, ref, args, kw, sc, ph, node):
    target = args[0] if args else Val()
    if ref.endswith("run_module"):
        name = conc(target)
        if isinstance(name, str) and self.local_module(name):
            self.load_module(name, ph)
            return Val()
        return self.exec_code(V(NOVAL, frozenset({LOCAL})), ph, node, sc)
    return self.exec_code(V(NOVAL, self.open_file(target, "r", ph, node).tags, fromfile=target), ph, node, sc)


@_h("importlib.machinery.SourceFileLoader", "importlib.util.spec_from_file_location", "imp.load_source")
def _h_file_loader(self, ref, args, kw, sc, ph, node):
    """A module loaded from a file path (any suffix): its code runs when the loader's load_module / exec_module is
    called - imp.load_source runs it at once."""
    pv = _arg(args, kw, 1, "location" if ref.endswith("location") else "path" if ref.endswith("Loader") else "pathname")
    if ref == "imp.load_source":
        self.exec_code(V(NOVAL, self.open_file(pv, "r", ph, node).tags, fromfile=pv), ph, node, sc)
        return Val()
    return V(ref="#loader", path=pv)


@_h(*PROCESS)
def _h_process(self, ref, args, kw, sc, ph, node):
    name = ref.rsplit(".", 1)[-1]
    if name.startswith(("spawn", "exec")) and ref.startswith("os."):
        rest = [a for a in args if not (a.known and isinstance(a.c, int))]
        flat = []
        for a in rest[1:] if name in ("execv", "execve", "execvp", "execvpe", "spawnv", "spawnve", "spawnvp",
                                      "spawnvpe") else rest:
            items = self.iter_items(a) if a.known and isinstance(a.c, (list, tuple)) else None
            flat.extend(items if items is not None else [a])
        if name in ("execv", "execve", "execvp", "execvpe", "spawnv", "spawnve", "spawnvp", "spawnvpe") and len(rest) > 1:
            items = self.iter_items(rest[1]) if rest[1].known else None
            flat = [rest[0]] + (items[1:] if items else [rest[1]])
        cmd = Val(flat, T(*flat))
    elif name == "spawn" and ref == "pty.spawn":
        cmd = args[0] if args else Val()
    else:
        cmd = _arg(args, kw, 0, "args")
    return self.run_process(cmd, ph, node, kw.get("shell"), kw, ref)


@_h("os.dup2")
def _h_dup2(self, ref, args, kw, sc, ph, node):
    if args and SOCK in args[0].tags:
        self.emit("remote_shell", ph, node)
    return Val()


@_h("builtins.getattr")
def _h_getattr(self, ref, args, kw, sc, ph, node):
    if len(args) < 2:
        return Val()
    obj, nm = args[0], args[1]
    names = [c.c for c in cands(nm) if isinstance(c.c, str)]
    if not names:
        return V(NOVAL, obj.tags | nm.tags)
    lit = node.args[1] if len(node.args) > 1 else None
    # a plain literal name is the compatibility idiom (six: getattr(moves.builtins, "exec")); a computed or escaped one hides
    plain = isinstance(lit, ast.Constant) and self.src(lit)[1:-1] == lit.value
    if obj.ref == "#mod":
        interp = M(obj, "interp")
        v = interp.glob.vars.get(names[0]) if interp is not None else None
        return v or Val()
    r = self.attr(obj, names[0], node, sc)
    if r.ref and r.ref[0] != "#" and not plain:
        r = Val(r.c, r.tags, r.ref, dict(r.meta or {}, hidden=True))
    return r


@_h("builtins.__import__", "importlib.import_module", "importlib.__import__")
def _h_import(self, ref, args, kw, sc, ph, node):
    nm = args[0] if args else Val()
    names = [c.c for c in cands(nm) if isinstance(c.c, str)]
    if not names:
        return V(NOVAL, nm.tags)
    lit = node.args[0] if node.args else None
    plain = isinstance(lit, ast.Constant) and self.src(lit)[1:-1] == lit.value
    mod = names[0]
    local = self.local_module(mod)
    if local:
        return self.load_module(local, ph)
    if ref == "builtins.__import__" and not (len(args) > 3 and conc(args[3])):
        mod = mod.split(".")[0] if "." in mod else mod
    return V(ref=canon(mod), hidden=True) if not plain else V(ref=canon(mod))


@_h("builtins.vars")
def _h_vars(self, ref, args, kw, sc, ph, node):
    return V(ref="#vars", of=args[0]) if args else V(ref="#globals")


@_h("builtins.globals", "builtins.locals")
def _h_globals(self, ref, args, kw, sc, ph, node):
    return V(ref="#globals")


@_h("builtins.open", "io.open", "codecs.open", "os.fdopen", "gzip.open", "bz2.open", "lzma.open", "aiofiles.open")
def _h_open(self, ref, args, kw, sc, ph, node):
    pv = _arg(args, kw, 0, "file")
    mode = conc(_arg(args, kw, 1, "mode", Val("r")))
    return self.open_file(pv, mode if isinstance(mode, str) else "r", ph, node)


@_h("sqlite3.connect")
def _h_sqlite(self, ref, args, kw, sc, ph, node):
    return V(NOVAL, self.open_file(args[0] if args else Val(), "r", ph, node).tags)


@_h("builtins.chr")
def _h_chr(self, ref, args, kw, sc, ph, node):
    c = conc(args[0]) if args else NOVAL
    tags = T(*args) | {DECODED}
    if isinstance(c, int) and 0 <= c < 0x110000:
        return Val(chr(c), tags)
    return V(NOVAL, tags)


@_h("builtins.ord")
def _h_ord(self, ref, args, kw, sc, ph, node):
    c = conc(args[0]) if args else NOVAL
    if isinstance(c, (str, bytes)) and len(c) == 1:
        return Val(ord(c), T(*args))
    return V(NOVAL, T(*args))


@_h("builtins.bytes", "builtins.bytearray")
def _h_bytes(self, ref, args, kw, sc, ph, node):
    if not args:
        return Val(b"")
    c = conc(args[0])
    tags = T(*args)
    if isinstance(c, (list, tuple)) and all(isinstance(x, int) and 0 <= x < 256 for x in c):
        return Val(bytes(c), tags | {DECODED})
    if isinstance(c, str) and len(args) > 1:
        try:
            return Val(c.encode(conc(args[1])), tags)
        except Exception:
            return V(NOVAL, tags)
    if isinstance(c, (bytes, bytearray)):
        return Val(bytes(c), tags)
    if isinstance(c, int) and c <= self.lim["max_string"]:
        return Val(bytes(c), tags)
    if args[0].ref == "os.environ":
        return V(NOVAL, {SECRET})
    return V(NOVAL, tags)


@_h("builtins.str", "builtins.repr", "builtins.ascii", "builtins.format", "json.dumps", "builtins.dict",
    "builtins.list", "builtins.tuple", "builtins.set", "builtins.frozenset", "builtins.sorted", "builtins.reversed",
    "builtins.iter", "builtins.int", "builtins.float", "builtins.bool", "builtins.hex", "builtins.oct", "builtins.bin",
    "builtins.len", "builtins.sum", "builtins.min", "builtins.max", "builtins.abs", "builtins.round", "builtins.next",
    "builtins.enumerate", "builtins.zip", "builtins.range", "builtins.any", "builtins.all", "json.loads",
    "builtins.isinstance", "builtins.hasattr", "builtins.callable", "builtins.print", "builtins.type",
    "builtins.divmod", "builtins.pow")
def _h_builtin(self, ref, args, kw, sc, ph, node):
    name = ref.rsplit(".", 1)[-1]
    if any(a.ref == "os.environ" for a in args) and name == "dict":
        return V(NOVAL, {SECRET}, "os.environ")          # a copy: still read by name (env.get("X")) like the original
    if any(a.ref == "os.environ" for a in args) and name in ("str", "repr", "list", "tuple", "sorted",
                                                             "dumps", "iter", "set", "format"):
        return V(NOVAL, {SECRET})
    if name in ("isinstance", "hasattr", "callable", "print", "type", "any", "all"):
        return Val()
    tags = T(*args, *kw.values())
    if name in ("repr", "dumps", "ascii"):
        tags = tags - {NET, DECODED}                 # a quoted literal: data pasted into code this way stays data
    cargs = [conc(a) for a in args]
    if any(c is NOVAL for c in cargs) or any(conc(v) is NOVAL for v in kw.values()):
        if name in ("list", "tuple", "sorted", "reversed", "iter", "set", "frozenset") and args:
            items = self.iter_items(args[0])
            if items is not None:
                if name == "reversed":
                    items = list(reversed(items))
                return Val(list(items), T(*items) | args[0].tags)
            return V(NOVAL, tags, None, alts=M(args[0], "alts")) if M(args[0], "alts") else V(NOVAL, tags,
                                                                                              partial=M(args[0], "partial"))
        if name in ("str", "format") and args and M(args[0], "partial"):
            return args[0]
        if name == "zip" and all(a.known and isinstance(a.c, (list, tuple)) for a in args):
            pairs = [Val(tuple(t), T(*t)) for t in zip(*[a.c for a in args])]
            return Val(pairs, tags)
        if name == "enumerate" and args and args[0].known and isinstance(args[0].c, (list, tuple)):
            return Val([Val((Val(i), x), x.tags) for i, x in enumerate(args[0].c)], tags)
        if name == "dict" and kw:
            return Val(dict(kw), tags)
        if name == "next" and args:
            return self.element(args[0])
        if name == "str" and args and args[0].ref == "#path":
            return Val(args[0].c, args[0].tags, None, args[0].meta) if args[0].known else V(NOVAL, args[0].tags,
                                                                                           partial=M(args[0], "partial"))
        return V(NOVAL, tags)
    if name == "range":
        try:
            r = range(*cargs)
        except (TypeError, ValueError):
            return Val()
        if len(r) > self.lim["max_iter"]:
            return Val()
        return Val([Val(i) for i in r])
    if name == "dumps":
        import json
        try:
            return wrap(json.dumps(cargs[0], **{k: conc(v) for k, v in kw.items() if k in ("indent", "sort_keys")}),
                        tags, self.lim)
        except (TypeError, ValueError):
            return V(NOVAL, tags)
    if name == "loads":
        import json
        try:
            return wrap(json.loads(cargs[0]), tags, self.lim)
        except (TypeError, ValueError):
            return V(NOVAL, tags)
    if name == "str" and args and args[0].ref == "#path":
        return Val(cargs[0], tags)
    if name in ("str",) and len(cargs) >= 2 and isinstance(cargs[0], bytes):
        try:
            return Val(cargs[0].decode(cargs[1]), tags)
        except Exception:
            return V(NOVAL, tags)
    if name in ("list", "tuple", "sorted", "reversed", "iter", "set", "frozenset") and args:
        items = self.iter_items(args[0])
        if items is not None:
            if name == "reversed":
                items = list(reversed(items))
            if name == "sorted":
                try:
                    items = sorted(items, key=lambda v: conc(v), reverse=bool(conc(kw.get("reverse", Val(False)))))
                except TypeError:
                    return V(NOVAL, tags)
            return Val(tuple(items) if name == "tuple" else list(items), tags)
        return V(NOVAL, tags)
    if name == "dict":
        items = self.iter_items(args[0]) if args else []
        d = {}
        if args and args[0].known and isinstance(args[0].c, dict):
            d.update(args[0].c)
        elif items:
            for it in items:
                pair = conc(it)
                if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                    return V(NOVAL, tags)
                d[pair[0]] = it.c[1] if isinstance(it.c, (list, tuple)) else wrap(pair[1])
        d.update(kw)
        return Val(d, tags)
    if name == "zip":
        return Val([Val(tuple(t), T(*t)) for t in zip(*[a.c for a in args])], tags) if all(
            isinstance(a.c, (list, tuple)) for a in args) else V(NOVAL, tags)
    if name == "enumerate":
        items = self.iter_items(args[0]) or []
        return Val([Val((Val(i), x), x.tags) for i, x in enumerate(items)], tags)
    if name == "next":
        items = self.iter_items(args[0]) if args else None
        return items[0] if items else Val()
    if name == "int" and len(cargs) == 2 and isinstance(cargs[0], (str, bytes)) and len(cargs[0]) > 5000:
        return V(NOVAL, tags)
    if name == "pow" and len(cargs) >= 2 and isinstance(cargs[1], int) and cargs[1] > 4096 and len(cargs) == 2:
        return V(NOVAL, tags)
    fn = {"str": str, "repr": repr, "ascii": ascii, "format": format, "int": int, "float": float, "bool": bool,
          "hex": hex, "oct": oct, "bin": bin, "len": len, "sum": sum, "min": min, "max": max, "abs": abs,
          "round": round, "divmod": divmod, "pow": pow, "isinstance": None}.get(name)
    if fn is None:
        return V(NOVAL, tags)
    if name == "format" and len(cargs) > 1 and not _fmt_ok(str(cargs[1])):
        return V(NOVAL, tags)
    try:
        return wrap(fn(*cargs), tags, self.lim)
    except Exception:
        return V(NOVAL, tags)


@_h("builtins.map")
def _h_map(self, ref, args, kw, sc, ph, node):
    if len(args) < 2:
        return Val()
    fv = args[0]
    seqs = [self.iter_items(a) for a in args[1:]]
    if any(s is None for s in seqs) or sum(len(s) for s in seqs) + self.iters > self.lim["max_iter"]:
        out = self.apply(fv, [self.element(a) for a in args[1:]], {}, sc, ph, node)
        return V(NOVAL, out.tags | T(*args[1:]))
    out = []
    for items in zip(*seqs):
        self.iters += 1
        self.tick()
        out.append(self.apply(fv, list(items), {}, sc, ph, node))
    return Val(out, T(*out))


@_h("builtins.filter")
def _h_filter(self, ref, args, kw, sc, ph, node):
    items = self.iter_items(args[1]) if len(args) > 1 else None
    if items is None:
        return V(NOVAL, T(*args[1:]))
    out = []
    for it in items:
        r = conc(self.apply(args[0], [it], {}, sc, ph, node)) if args[0].known is False or args[0].ref else conc(it)
        if r is NOVAL:
            return V(NOVAL, T(*items))
        if r:
            out.append(it)
    return Val(out, T(*out))


@_h("functools.reduce")
def _h_reduce(self, ref, args, kw, sc, ph, node):
    items = self.iter_items(args[1]) if len(args) > 1 else None
    if items is None:
        return V(NOVAL, T(*args[1:]))
    acc = args[2] if len(args) > 2 else (items.pop(0) if items else Val())
    for it in items:
        self.iters += 1
        acc = self.apply(args[0], [acc, it], {}, sc, ph, node)
    return acc


# --- decoders
def const_origin(v: Val) -> bool:
    """Made from constants or the package's own files - an embedded blob - rather than data flowing in at run time
    (a cache entry, a database value, a .pyc): decoding that is hiding, decoding data is serialization."""
    partial = M(v, "partial") or ""
    return v.known or len(partial.replace(PH, "")) >= 24 or bool(v.tags & {OPAQUE, LOCAL, DECODED})


def _decode(self, fn, args, tags_extra=()):
    data = args[0] if args else Val()
    tags = data.tags | ({DECODED} if const_origin(data) else set()) | set(tags_extra)
    c = conc(data)
    if isinstance(c, str):
        c = c.encode("latin-1", "replace")
    if not isinstance(c, (bytes, bytearray)):
        return V(NOVAL, tags)
    try:
        r = fn(bytes(c))
    except Exception:
        return V(NOVAL, tags)
    return wrap(r, tags, self.lim) if r is not None else V(NOVAL, tags)


def _b64(data: bytes, alt=None):
    data = re.sub(rb"\s+", b"", data)
    if alt:
        data = data.translate(bytes.maketrans(alt, b"+/"))
    return base64.b64decode(data + b"=" * (-len(data) % 4))


@_h("base64.b64decode", "base64.decodebytes", "base64.decodestring", "base64.standard_b64decode",
    "base64.urlsafe_b64decode", "base64.b32decode", "base64.b16decode", "base64.b85decode", "base64.a85decode",
    "base64.b32hexdecode", "binascii.a2b_base64", "binascii.unhexlify", "binascii.a2b_hex", "bytes.fromhex",
    "builtins.bytes.fromhex", "builtins.bytearray.fromhex",
    "codecs.decode", "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress", "codecs.encode")
def _h_decoder(self, ref, args, kw, sc, ph, node):
    lim = self.lim["max_string"]
    name = ref.rsplit(".", 1)[-1]
    if ref in ("codecs.decode", "codecs.encode"):
        codec = str(conc(_arg(args, kw, 1, "encoding", Val("utf-8")))).lower().replace("-", "_")
        data = args[0] if args else Val()
        if codec in ("utf_8", "utf8", "ascii", "latin_1", "latin1"):
            c = conc(data)
            if isinstance(c, bytes) and ref == "codecs.decode":
                return Val(c.decode(codec, "replace"), data.tags)
            if isinstance(c, str) and ref == "codecs.encode":
                return Val(c.encode(codec, "replace"), data.tags)
            return V(NOVAL, data.tags)
        if codec not in DECODE_CODECS or ref == "codecs.encode" and not codec.startswith("rot"):
            return V(NOVAL, data.tags) if conc(data) is NOVAL else _h_encoder(self, "binascii.hexlify", args, {}, sc, ph,
                                                                               node) if codec.startswith("hex") else \
                V(NOVAL, data.tags)
        if codec.startswith(("zlib", "bz2")):
            return _decode(self, lambda b: _limited_decompress("zlib" if codec.startswith("zlib") else "bz2", b, lim), args)
        c = conc(data)
        dec = {DECODED} if const_origin(data) else set()
        if c is NOVAL or len(str(c)) > lim:
            return V(NOVAL, data.tags | dec)
        try:
            return wrap(codecs.decode(c, codec) if ref == "codecs.decode" else codecs.encode(c, codec),
                        data.tags | dec, self.lim)
        except Exception:
            return V(NOVAL, data.tags | dec)
    if name in ("decompress",):
        kind = {"zlib": "zlib", "gzip": "zlib", "bz2": "bz2", "lzma": "lzma"}[ref.split(".")[0]]
        return _decode(self, lambda b: _limited_decompress(kind, b, lim), args)
    alt = kw.get("altchars") or (args[1] if len(args) > 1 and name in ("b64decode",) else None)
    altc = conc(alt) if alt is not None else None
    fns = {"b64decode": lambda b: _b64(b, altc if isinstance(altc, bytes) else None),
           "decodebytes": _b64, "decodestring": _b64, "standard_b64decode": _b64, "a2b_base64": _b64,
           "urlsafe_b64decode": lambda b: _b64(b, b"-_"),
           "b32decode": lambda b: base64.b32decode(b + b"=" * (-len(b) % 8), casefold=True),
           "b32hexdecode": lambda b: base64.b32hexdecode(b + b"=" * (-len(b) % 8), casefold=True),
           "b16decode": lambda b: base64.b16decode(b, casefold=True), "b85decode": base64.b85decode,
           "a85decode": base64.a85decode, "unhexlify": lambda b: binascii.unhexlify(re.sub(rb"\s+", b"", b)),
           "a2b_hex": binascii.a2b_hex, "fromhex": lambda b: bytes.fromhex(b.decode("latin-1"))}
    return _decode(self, fns[name], args)


@_h("base64.b64encode", "base64.encodebytes", "base64.urlsafe_b64encode", "base64.b32encode", "base64.b16encode",
    "binascii.hexlify", "binascii.b2a_hex", "binascii.b2a_base64", "zlib.compress", "urllib.parse.quote",
    "urllib.parse.quote_plus", "urllib.parse.urlencode", "base64.standard_b64encode")
def _h_encoder(self, ref, args, kw, sc, ph, node):
    data = args[0] if args else Val()
    if data.ref == "os.environ":
        return V(NOVAL, {SECRET})
    tags = _deep_tags(data) | T(*args[1:])
    c = conc(data)
    name = ref.rsplit(".", 1)[-1]
    if c is NOVAL:
        if name in ("urlencode",) and data.known:
            return V(NOVAL, tags, partial="&".join(f"{k}={text(v) or PH}" for k, v in data.c.items())
                     if isinstance(data.c, dict) else None)
        return V(NOVAL, tags, partial=M(data, "partial")) if name.startswith("quote") else V(NOVAL, tags)
    try:
        fn = {"b64encode": base64.b64encode, "encodebytes": base64.encodebytes, "urlsafe_b64encode": base64.urlsafe_b64encode,
              "standard_b64encode": base64.standard_b64encode, "b32encode": base64.b32encode,
              "b16encode": base64.b16encode, "hexlify": binascii.hexlify, "b2a_hex": binascii.b2a_hex,
              "b2a_base64": binascii.b2a_base64, "compress": zlib.compress}.get(name)
        if fn is not None:
            if isinstance(c, str):
                c = c.encode()
            return wrap(fn(c), tags, self.lim)
        from urllib import parse
        return wrap(getattr(parse, name)(c), tags, self.lim)
    except Exception:
        return V(NOVAL, tags)


# --- environment, system information, paths
@_h("os.getenv", "os.environ.get", "os.getenvb")
def _h_getenv(self, ref, args, kw, sc, ph, node):
    return self.env_get(args[0] if args else Val(), args[1] if len(args) > 1 else kw.get("default"))


@_h(*SYSINFO_CALLS)
def _h_sysinfo(self, ref, args, kw, sc, ph, node):
    return V(NOVAL, {SYSINFO})


@_h("os.path.expanduser", "os.path.expandvars", "os.path.abspath", "os.path.realpath", "os.path.normpath",
    "os.fspath", "os.path.normcase")
def _h_path_same(self, ref, args, kw, sc, ph, node):
    v = args[0] if args else Val()
    t = text(v)
    if ref.endswith("expandvars") and t:
        t = re.sub(r"\$\{?(HOME|USERPROFILE)\}?|%(USERPROFILE|HOMEPATH)%", "~", t, flags=re.I)
        t = re.sub(r"%APPDATA%|\$\{?APPDATA\}?", "~/appdata/roaming", t, flags=re.I)
        t = re.sub(r"%LOCALAPPDATA%|\$\{?LOCALAPPDATA\}?", "~/appdata/local", t, flags=re.I)
        return Val(t, v.tags | path_tags(t)) if v.known else V(NOVAL, v.tags | path_tags(t), partial=t)
    if v.known and isinstance(v.c, str):
        return Val(v.c, v.tags | path_tags(v.c))
    return Val(v.c, v.tags, None, v.meta) if not v.ref else V(NOVAL, v.tags, partial=t)


@_h("os.path.join", "posixpath.join", "ntpath.join")
def _h_join(self, ref, args, kw, sc, ph, node):
    parts = [text(a) if text(a) is not None else PH for a in args]
    out = ""
    for p in parts:
        out = p if p.startswith(("/", "~")) or re.match(r"^[A-Za-z]:[\\/]", p) else (out.rstrip("/\\") + "/" + p if out else p)
    tags = T(*args) | path_tags(out)
    if all(a.known for a in args):
        return Val(out, tags)
    return V(NOVAL, tags, partial=out)


@_h("os.path.dirname", "os.path.basename")
def _h_dirname(self, ref, args, kw, sc, ph, node):
    v = args[0] if args else Val()
    t = text(v)
    if t is None:
        return V(NOVAL, v.tags)
    t = t.replace("\\", "/")
    r = (t.rsplit("/", 1)[0] if "/" in t else "") if ref.endswith("dirname") else t.rsplit("/", 1)[-1]
    return Val(r, v.tags) if v.known else V(NOVAL, v.tags, partial=r)


@_h("pathlib.Path", "pathlib.Path.home", "pathlib.Path.cwd")
def _h_pathlib(self, ref, args, kw, sc, ph, node):
    if ref.endswith(".home"):
        return self.mkpath("~")
    if ref.endswith(".cwd"):
        return V(NOVAL, {SYSINFO}, "#path", partial=PH)
    out = None
    for a in args or [Val(".")]:
        p = a if a.ref == "#path" else self.mkpath(text(a) if text(a) is not None else PH, a)
        out = p if out is None else self.binop(ast.Div(), out, p)
    return out


@_h("glob.glob", "glob.iglob", "os.listdir", "os.scandir", "os.walk")
def _h_glob(self, ref, args, kw, sc, ph, node):
    pv = args[0] if args else Val(".")
    t = text(pv) or ""
    tags = pv.tags | path_tags(t) | path_tags(t.rstrip("/") + "/x")
    return V(NOVAL, tags, partial=(t.rstrip("/") + "/" + PH) if t else None)


@_h("tempfile.gettempdir")
def _h_tmpdir(self, ref, args, kw, sc, ph, node):
    return Val("/tmp")


@_h("tempfile.mktemp", "tempfile.mkdtemp")
def _h_mktemp(self, ref, args, kw, sc, ph, node):
    suffix = text(kw.get("suffix", Val(""))) or ""
    return V(NOVAL, partial="/tmp/" + PH + suffix)


@_h("tempfile.NamedTemporaryFile", "tempfile.TemporaryFile", "tempfile.SpooledTemporaryFile")
def _h_tempfile(self, ref, args, kw, sc, ph, node):
    suffix = text(kw.get("suffix", Val(""))) or ""
    return Val(NOVAL, frozenset(), "#file", {"path": V(NOVAL, partial="/tmp/" + PH + suffix), "mode": "w+b",
                                              "written": frozenset()})


@_h("tempfile.mkstemp")
def _h_mkstemp(self, ref, args, kw, sc, ph, node):
    suffix = text(kw.get("suffix", Val(""))) or ""
    return Val((Val(3), V(NOVAL, partial="/tmp/" + PH + suffix)))


@_h("shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move", "os.rename", "os.replace", "os.link",
    "os.symlink", "shutil.copytree")
def _h_copy(self, ref, args, kw, sc, ph, node):
    if len(args) < 2:
        return Val()
    src, dst = args[0], args[1]
    data = V(NOVAL, self.open_file(src, "r", ph, node).tags - {FILE, LOCAL})
    self.write_file(dst, data, ph, node)
    return Val()


@_h("shutil.rmtree", "os.remove", "os.unlink", "os.removedirs", "os.rmdir")
def _h_remove(self, ref, args, kw, sc, ph, node):
    target = args[0] if args else kw.get("path")
    if target is not None and any(wipe_target(t) for t in texts(target)):
        self.emit("wipe", ph, node)
    return Val()


@_h("shutil.copyfileobj")
def _h_copyfileobj(self, ref, args, kw, sc, ph, node):
    if len(args) >= 2 and args[1].ref == "#file":
        self.write_file(M(args[1], "path") or Val(), args[0], ph, node, args[1])
    return Val()


@_h("os.chmod", "os.chown")
def _h_chmod(self, ref, args, kw, sc, ph, node):
    for t in texts(args[0] if args else Val()):
        self.ctx.mark_executable(t)
    return Val()


@_h("zipfile.ZipFile", "tarfile.open", "shutil.make_archive")
def _h_zip(self, ref, args, kw, sc, ph, node):
    if ref == "shutil.make_archive":
        root = _arg(args, kw, 2, "root_dir")
        tags = {SECRET} if any(path_class(t) == "credential" for t in texts(root)) or CRED_PATH in root.tags else set()
        base = args[0] if args else Val()
        fmt = conc(_arg(args, kw, 1, "format", Val("zip")))
        out = self.binop(ast.Add(), base, Val("." + (fmt if isinstance(fmt, str) else "zip")))
        self.taint_path(out, tags)
        return Val(out.c, out.tags | frozenset(tags), None, out.meta)
    pv = args[0] if args else Val()
    return V(NOVAL, frozenset(), "#zip", path=pv)


# --- network
@_h("urllib.request.urlopen")
def _h_urlopen(self, ref, args, kw, sc, ph, node):
    return self.h_urlopen(ref, args, kw, sc, ph, node)


@_h("urllib.request.Request")
def _h_request(self, ref, args, kw, sc, ph, node):
    url = _arg(args, kw, 0, "url")
    payload = [x for x in (args[1:3] + [kw.get("data"), kw.get("headers")]) if x is not None]
    return V(NOVAL, T(url), "#request", url=url, payload=payload)


@_h("requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient", "urllib3.PoolManager",
    "aiohttp.ClientSession", "urllib3.ProxyManager")
def _h_session(self, ref, args, kw, sc, ph, node):
    return V(ref="#http", mod=ref.split(".")[0], base=kw.get("base_url"))


@_h("os.environ.copy", "os.environ.items", "os.environ.keys", "os.environ.values")
def _h_environ_all(self, ref, args, kw, sc, ph, node):
    if ref.endswith(".copy"):
        return V(NOVAL, {SECRET}, "os.environ")
    return V(NOVAL, {SECRET}, environ=True)


@_h("textwrap.dedent", "textwrap.indent", "inspect.cleandoc", "string.Template")
def _h_text(self, ref, args, kw, sc, ph, node):
    import inspect
    import textwrap
    c = [conc(a) for a in args]
    if not c or any(x is NOVAL for x in c) or ref == "string.Template":
        return V(NOVAL, T(*args), partial=M(args[0], "partial") if args else None)
    fn = {"textwrap.dedent": textwrap.dedent, "textwrap.indent": textwrap.indent, "inspect.cleandoc": inspect.cleandoc}[ref]
    try:
        return wrap(fn(*c), T(*args), self.lim)
    except Exception:
        return V(NOVAL, T(*args))


@_h("urllib.request.build_opener")
def _h_opener(self, ref, args, kw, sc, ph, node):
    return V(ref="#opener")


@_h("urllib.request.urlretrieve", "wget.download")
def _h_urlretrieve(self, ref, args, kw, sc, ph, node):
    url = _arg(args, kw, 0, "url")
    self.send(url, [url], ph, node)
    dst = _arg(args, kw, 1, "filename" if ref.startswith("urllib") else "out")
    if dst.known or M(dst, "partial"):
        self.taint_path(dst, {NET})
    return Val((Val(dst.c, dst.tags | {NET_FILE}, None, dst.meta), V(NOVAL, {NET})), frozenset({NET}),
               None, {"pair": [Val(dst.c, dst.tags | {NET_FILE}, None, dst.meta), V(NOVAL, {NET})]})


@_h("http.client.HTTPConnection", "http.client.HTTPSConnection")
def _h_httpconn(self, ref, args, kw, sc, ph, node):
    host = _arg(args, kw, 0, "host")
    scheme = "https://" if ref.endswith("HTTPSConnection") else "http://"
    return V(NOVAL, frozenset(), "#httpconn", host=self.binop(ast.Add(), Val(scheme), host))


@_h("socket.socket", "socket.create_connection", "ssl.wrap_socket")
def _h_socket(self, ref, args, kw, sc, ph, node):
    meta = {}
    if ref.endswith("create_connection") and args:
        a = args[0]
        meta["host"] = a.c[0] if a.known and isinstance(a.c, (list, tuple)) and a.c else a
    return Val(NOVAL, frozenset({SOCK}), "#sock", meta)


@_h("socket.gethostbyname", "socket.getaddrinfo", "socket.gethostbyname_ex", "dns.resolver.resolve",
    "dns.resolver.query")
def _h_dns(self, ref, args, kw, sc, ph, node):
    name = args[0] if args else Val()
    if name.tags & {SECRET, SECRET_ENV, SYSINFO}:
        self.send(name, [name], ph, node)
    return V(NOVAL, {NET})


@_h("smtplib.SMTP", "smtplib.SMTP_SSL")
def _h_smtp(self, ref, args, kw, sc, ph, node):
    return V(NOVAL, frozenset(), "#smtp", host=_arg(args, kw, 0, "host"))


@_h("ftplib.FTP", "ftplib.FTP_TLS")
def _h_ftp(self, ref, args, kw, sc, ph, node):
    return V(NOVAL, frozenset(), "#smtp", host=_arg(args, kw, 0, "host"))


@_h("winreg.OpenKey", "winreg.CreateKey", "winreg.OpenKeyEx", "winreg.CreateKeyEx")
def _h_regkey(self, ref, args, kw, sc, ph, node):
    sub = args[1] if len(args) > 1 else Val()
    t = text(sub) or ""
    return Val(NOVAL, path_tags(t), "#regkey", {"key": t})


@_h("winreg.SetValueEx", "winreg.SetValue")
def _h_regset(self, ref, args, kw, sc, ph, node):
    key = args[0] if args else Val()
    if AUTOSTART_PATH in key.tags or path_class(M(key, "key") or "") == "autostart":
        self.emit("persistence", ph, node)
    return Val()


@_h("setuptools.setup", "distutils.core.setup")
def _h_setup(self, ref, args, kw, sc, ph, node):
    """setup(cmdclass={...}): the command classes' methods run during the build / install."""
    cmd = kw.get("cmdclass")
    for cv in (cmd.c.values() if cmd is not None and cmd.known and isinstance(cmd.c, dict) else []):
        ci = M(cv, "cls")
        if not isinstance(ci, ClassInfo):
            continue
        inst = V(ref="#inst", cls=ci)
        for v in list(ci.scope.vars.values()):
            fn = M(v, "func")
            if fn is not None and isinstance(fn.node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                n = len(fn.node.args.args) - 1
                self.invoke(fn, [Val() for _ in range(max(n, 0))], {}, ph, inst)
    return Val()


# --- things that run a local function later at the same phase
@_h("threading.Thread", "multiprocessing.Process", "threading.Timer", "atexit.register", "signal.signal",
    "asyncio.run", "asyncio.get_event_loop", "concurrent.futures.ThreadPoolExecutor")
def _h_runs_later(self, ref, args, kw, sc, ph, node):
    target = kw.get("target") or (args[1] if ref == "threading.Timer" and len(args) > 1 else
                                  args[1] if ref == "signal.signal" and len(args) > 1 else args[0] if args else None)
    targs = kw.get("args") or (args[1:] and Val(list(args[1:])) if ref == "atexit.register" else None)
    if target is not None and M(target, "func") is not None:
        items = self.iter_items(targs) if targs is not None else []
        self.invoke(M(target, "func"), items or [], {}, ph, M(target, "bound"))
    elif target is not None and target.ref and target.ref[0] != "#" and ref != "signal.signal":
        # a library function handed over by reference (atexit.register(os.system, cmd)): the same as calling it
        items = self.iter_items(targs) if targs is not None else []
        tkw = kw.get("kwargs")
        tkw = {str(k): v for k, v in tkw.c.items()} if tkw is not None and tkw.known and isinstance(tkw.c, dict) else {}
        if ref == "atexit.register":
            tkw = {k: v for k, v in kw.items() if k != "args"}
        self.apply(target, items or [], tkw, sc, ph, node)
    return Val()


# --- C functions reached through ctypes: ctypes.CDLL(None).system(b"...") is os.system
LIBC = {"system": "os.system", "popen": "os.popen", "execl": "os.execl", "execlp": "os.execlp", "execv": "os.execv",
        "execvp": "os.execvp", "execve": "os.execve", "posix_spawn": "os.posix_spawn", "posix_spawnp": "os.posix_spawnp"}


@_h("sys.path.insert", "sys.path.append", "site.addsitedir")
def _h_syspath(self, ref, args, kw, sc, ph, node):
    """A package folder put on the import path (sys.path.insert(0, 'tests')): its modules become importable by their
    short names, so `import helper` then loads tests/helper.py."""
    d = args[1] if ref == "sys.path.insert" and len(args) > 1 else args[0] if args else Val()
    for t in texts(d)[:4]:
        parts = [x for x in t.split(PH)[-1].replace("\\", "/").split("/") if x not in ("", ".")]
        for k in range(len(parts)):                      # the folder from the package root, else its trailing folders
            prefix = ".".join(parts[k:]) + "."
            hits = {n[len(prefix):]: v for n, v in self.ctx.modules.items() if n.startswith(prefix)}
            if hits:
                for n, v in hits.items():
                    self.ctx.modules.setdefault(n, v)
                break
    return Val()


@_h("ctypes.CDLL", "ctypes.PyDLL", "ctypes.cdll.LoadLibrary", "ctypes.pydll.LoadLibrary", "ctypes.LibraryLoader")
def _h_dll(self, ref, args, kw, sc, ph, node):
    return V(ref="#dll")


# --- whole module names that are values, not calls
def _parse(source: str):
    """ast.parse; a statement nested too deep for the parser (a 20,000-part string concatenation) is replaced by
    `name = None` / `pass` so the rest of the file is still read."""
    try:
        return ast.parse(source)
    except (RecursionError, MemoryError):
        pass
    lines = source.splitlines()
    for i, ln in enumerate(lines):
        if len(ln) > 2000:
            m = re.match(r"^(\s*)([\w.]+)\s*=", ln)
            lines[i] = f"{m.group(1)}{m.group(2)} = None" if m else re.match(r"^\s*", ln).group(0) + "pass"
    try:
        return ast.parse("\n".join(lines))
    except (RecursionError, MemoryError):
        raise SyntaxError("too deep")


def analyze_source(ctx, source: str, file: str, phase: str, depth: int = 0, line_base=None, env=None,
                   loaded: bool = False) -> None:
    """Facts of one Python source into ctx. SyntaxError (Python 2 code is retried with print / except fixed) and
    other errors are recorded by the caller; LimitExceeded propagates so the caller records the file."""
    try:
        tree = _parse(source)
    except SyntaxError:
        fixed = re.sub(r"^(\s*)print\s+(?!\()([^\n]*)$", r"\1print(\2)", source, flags=re.M)
        fixed = re.sub(r"except\s+([\w.]+)\s*,\s*(\w+)\s*:", r"except \1 as \2:", fixed)
        fixed = re.sub(r"\b0([0-7]+)\b", r"0o\1", fixed)
        try:
            tree = _parse(fixed)
            source = fixed
        except SyntaxError:
            if depth == 0:
                ctx.not_analyzed.append((file, "syntax error"))
            return
    interp = Interp(ctx, file, phase, depth, line_base, source)
    interp.loaded = loaded
    top = depth == 0 and line_base is None
    if top:
        ctx.py_scopes[(file, phase)] = interp
    interp.run_module(tree, env, defer=top)


def finish(ctx) -> None:
    """The functions no top-level code reached, analyzed with unknown arguments (see Interp.leftovers)."""
    import time
    while ctx.py_pending:
        if time.monotonic() > ctx.deadline:
            ctx.not_analyzed.append(("*", f"time limit: functions of {len(ctx.py_pending)} files not analyzed"))
            ctx.py_pending.clear()
            break
        interp = ctx.py_pending.pop(0)
        try:
            interp.leftovers()
        except LimitExceeded as e:
            ctx.not_analyzed.append((interp.file, str(e)))
        except (RecursionError, MemoryError):
            ctx.not_analyzed.append((interp.file, "depth limit"))


__all__ = ["analyze_source", "finish", "Interp"]
