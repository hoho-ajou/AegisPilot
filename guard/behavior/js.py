"""JavaScript front end of the behavior analysis (guard/behavior): what a .js file does, without running it.

Standard library only (no external parser). A light tokenizer (strings with escapes, template literals, comments,
regex literals) feeds a Pratt parser that builds small tuple nodes; a statement that does not parse is skipped to the
next statement boundary. An abstract evaluator then walks the program with the shared value model (values.Val):

  values    literals, + and templates, string / array / Buffer methods, atob, String.fromCharCode, Buffer.from(..,
            'base64'|'hex'), zlib inflate/gunzip, decodeURIComponent; short local functions and arrows are evaluated with
            their arguments (depth limit), so `['ev','al'].join('')` or `x.split('').reverse().join('')` is a known value
  names     require / import aliases, destructuring, global / globalThis / window, process.mainModule.require,
            obj['ev' + 'al'], escaped identifiers and strings; a sensitive function reached through a computed or
            escaped name keeps a `hidden` mark
  flow      taint tags (NET, SECRET, SECRET_ENV, SYSINFO, DECODED, LOCAL, and CRED_PATH / AUTOSTART_PATH / SOCK for
            path and socket values) follow assignments, calls, callbacks (.on('data'), .then, await) and destructuring
  sinks     eval / Function / vm (a recovered string is analyzed again), child_process (a recovered command goes to
            shell.py), network sends, file writes -> the findings of rules/behavior.json

Phases: a file at "import" runs its top level, IIFEs, the functions the top level calls (transitively) and the
callbacks it hands to calls at that phase; every function never reached that way is analyzed afterwards at "call". A
file the install scripts run (or nested code) runs at the phase it was given.
"""
from __future__ import annotations

import base64
import bisect
import json
import re
import urllib.parse
import zlib

from . import LimitExceeded
from .values import (DECODED, LOCAL, NET, NOVAL, SECRET, SECRET_ENV, SYSINFO, UNKNOWN, Val, endpoint_class,
                     is_secret_env, path_class, policy)

CRED_PATH, AUTOSTART_PATH, SOCK = "CRED_PATH", "AUTOSTART_PATH", "SOCK"
# unreadable_exec is judged on these (python.py has the same): OPAQUE = computed from constants by code the analysis
# could not follow (a custom decoder); ENV = an environment variable's value (code handed in from outside)
OPAQUE, ENV = "OPAQUE", "ENV"
PH = "\x00"                                        # placeholder for an unknown part inside a partially known string


class _Undef:
    def __repr__(self):
        return "undefined"


UNDEF = _Undef()


class ParseError(Exception):
    pass


# ============================================================================================================ tokenizer

class Tok:
    __slots__ = ("t", "v", "pos", "nl", "esc")

    def __init__(self, t, v, pos, nl=False, esc=False):
        self.t, self.v, self.pos, self.nl, self.esc = t, v, pos, nl, esc

    def __repr__(self):
        return f"{self.t}:{self.v!r}"


PUNCS = sorted(""">>>= ... === !== **= <<= >>= >>> &&= ||= ??= => == != <= >= && || ?? ?. ++ -- += -= *= /= %= &= |= ^=
** << >> { } ( ) [ ] ; , < > + - * / % & | ^ ! ~ ? : = . @ #""".split(), key=len, reverse=True)
REGEX_AFTER = {"return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case", "do", "else",
               "yield", "await"}
_IDENT = re.compile(r"[A-Za-z_$\u0080-\uffff][\w$\u0080-\uffff]*")
_NUM = re.compile(r"0[xX][0-9a-fA-F_]+n?|0[bB][01_]+n?|0[oO][0-7_]+n?|(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d+)?n?")
_WS = re.compile(r"[ \t\r\f\v\u00a0\ufeff\u2028\u2029]+")
_IDENT_REST = re.compile(r"[\w$\u0080-\uffff]+")
_IDENT_ESC = re.compile(r"\\u(\{[0-9a-fA-F]{1,6}\}|[0-9a-fA-F]{4})")
_PUNC = re.compile("|".join(re.escape(p) for p in PUNCS))
_STR = {q: re.compile(q + r"(?:[^" + q + r"\\\n]|\\[\s\S])*(" + q + ")?") for q in "'\""}
_FLAGS = re.compile(r"[a-zA-Z]*")
_ESC = re.compile(r"\\(u\{[0-9a-fA-F]{1,6}\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[0-7]{1,3}|\r\n|[\s\S])")
_SIMPLE_ESC = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "\n": "", "\r\n": "", "\r": "",
               "\u2028": "", "\u2029": ""}


def unescape(raw: str) -> tuple[str, bool]:
    """Cooked text of a string body, and whether it used \\x / \\u / octal escapes (a hidden-name hint)."""
    hidden = False

    def sub(m):
        nonlocal hidden
        e = m.group(1)
        if e[0] == "u" and len(e) > 1:
            hidden = True
            try:
                return chr(int(e[2:-1] if e[1] == "{" else e[1:], 16))
            except (ValueError, OverflowError):
                return ""
        if e[0] == "x" and len(e) == 3:
            hidden = True
            return chr(int(e[1:], 16))
        if e[0] in "01234567":
            if e == "0":
                return "\0"
            hidden = True
            return chr(int(e, 8) & 0xFF)
        return _SIMPLE_ESC.get(e, e)
    if "\\" not in raw:
        return raw, False
    return _ESC.sub(sub, raw), hidden


def _regex_ok(prev: Tok | None) -> bool:
    if prev is None:
        return True
    if prev.t in ("num", "str", "tmpl", "regex"):
        return False
    if prev.t == "name":
        return prev.v in REGEX_AFTER
    return prev.v not in (")", "]", "++", "--")


def lex(src: str, pos: int = 0, in_tmpl: bool = False, deadline_check=None) -> tuple[list, int]:
    """Tokens of src from pos (inside a template `${`: up to its closing brace). Never raises on odd input."""
    toks: list[Tok] = []
    n = len(src)
    depth = 0
    nl = False
    if pos == 0 and src.startswith("#!"):
        pos = src.find("\n")
        pos = n if pos < 0 else pos
    count = 0
    while pos < n:
        count += 1
        if deadline_check and count % 20000 == 0:
            deadline_check()
        ch = src[pos]
        if ch == "\n":
            nl = True
            pos += 1
            continue
        m = _WS.match(src, pos)
        if m:
            pos = m.end()
            continue
        if ch == "/" and src.startswith("//", pos):
            e = src.find("\n", pos)
            pos = n if e < 0 else e
            continue
        if ch == "/" and src.startswith("/*", pos):
            e = src.find("*/", pos + 2)
            e = n if e < 0 else e
            if "\n" in src[pos:e]:
                nl = True
            pos = e + 2
            continue
        if ch == "<" and src.startswith("<!--", pos) or ch == "-" and src.startswith("-->", pos) and (nl or not toks):
            e = src.find("\n", pos)                   # HTML-like comments (Annex B)
            pos = n if e < 0 else e
            continue
        if in_tmpl and ch == "}" and depth == 0:
            return toks, pos + 1
        start = pos
        prev = toks[-1] if toks else None
        if ch == "\\" or _IDENT.match(ch):
            name, esc = [], False
            while pos < n:
                m = _IDENT.match(src, pos) if not name else _IDENT_REST.match(src, pos)
                if m:
                    name.append(m.group(0))
                    pos = m.end()
                    continue
                if src.startswith("\\u", pos):
                    m = _IDENT_ESC.match(src, pos)
                    if m:
                        try:
                            name.append(chr(int(m.group(1).strip("{}"), 16)))
                        except (ValueError, OverflowError):
                            pass
                        esc = True
                        pos = m.end()
                        continue
                break
            if not name:
                pos += 1
                continue
            toks.append(Tok("name", "".join(name), start, nl, esc))
        elif ch.isdigit() or (ch == "." and pos + 1 < n and src[pos + 1].isdigit()):
            m = _NUM.match(src, pos)
            text = m.group(0) if m else ch
            pos = start + len(text)
            toks.append(Tok("num", _num(text), start, nl))
        elif ch in "'\"":
            m = _STR[ch].match(src, pos)
            raw = src[pos + 1:m.end() - (1 if m.group(1) else 0)]
            pos = m.end()
            v, esc = unescape(raw)
            toks.append(Tok("str", v, start, nl, esc))
        elif ch == "`":
            parts, exprs, i, buf = [], [], pos + 1, []
            while i < n and src[i] != "`":
                if src[i] == "\\":
                    buf.append(src[i:i + 2])
                    i += 2
                elif src.startswith("${", i):
                    parts.append(unescape("".join(buf))[0])
                    buf = []
                    inner, i = lex(src, i + 2, True, deadline_check)
                    inner.append(Tok("eof", None, i))
                    exprs.append(inner)
                else:
                    buf.append(src[i])
                    i += 1
            parts.append(unescape("".join(buf))[0])
            pos = i + 1
            toks.append(Tok("tmpl", (parts, exprs), start, nl))
        elif ch == "/" and _regex_ok(prev):
            i, cls = pos + 1, False
            while i < n and src[i] != "\n":
                c = src[i]
                if c == "\\":
                    i += 2
                    continue
                if c == "[":
                    cls = True
                elif c == "]":
                    cls = False
                elif c == "/" and not cls:
                    break
                i += 1
            if i < n and src[i] == "/":
                body = src[pos + 1:i]
                i += 1
                m = _FLAGS.match(src, i)
                pos = m.end()
                toks.append(Tok("regex", (body, m.group(0)), start, nl))
            else:
                pos += 1
                toks.append(Tok("punc", "/", start, nl))
        else:
            m = _PUNC.match(src, pos)
            p = m.group(0) if m else ch
            if p == "?." and pos + 2 < n and src[pos + 2].isdigit():
                p = "?"
            pos += len(p)
            if p == "{":
                depth += 1
            elif p == "}":
                depth -= 1
            toks.append(Tok("punc", p, start, nl))
        nl = False
    return toks, pos


def _num(text: str):
    t = text.replace("_", "").rstrip("n")
    try:
        if t[:2].lower() == "0x":
            return int(t[2:], 16)
        if t[:2].lower() == "0b":
            return int(t[2:], 2)
        if t[:2].lower() == "0o":
            return int(t[2:], 8)
        if re.fullmatch(r"0[0-7]+", t):
            return int(t, 8)
        f = float(t)
        return int(f) if f.is_integer() and abs(f) < 2 ** 53 and "." not in t and "e" not in t.lower() else f
    except (ValueError, OverflowError):
        return float("nan")


# ============================================================================================================== parser

BINARY = {"??": 4, "||": 4, "&&": 5, "|": 6, "^": 7, "&": 8, "==": 9, "!=": 9, "===": 9, "!==": 9,
          "<": 10, ">": 10, "<=": 10, ">=": 10, "instanceof": 10, "in": 10,
          "<<": 11, ">>": 11, ">>>": 11, "+": 12, "-": 12, "*": 13, "/": 13, "%": 13, "**": 14}
ASSIGN = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>=", ">>>=", "&=", "|=", "^=", "&&=", "||=", "??="}
STMT_KEYWORDS = {"var", "let", "const", "if", "for", "while", "do", "return", "throw", "try", "switch", "break",
                 "continue", "function", "class", "import", "export", "debugger", "with"}
MAX_PARSE_DEPTH = 150


class Parser:
    """Tokens -> tuple nodes. Expressions: (kind, pos, ...); statements likewise. Unsupported syntax raises
    ParseError, caught by the nearest statement list, which skips to the next statement boundary."""

    def __init__(self, toks: list[Tok]):
        if not toks or toks[-1].t != "eof":
            toks = toks + [Tok("eof", None, toks[-1].pos if toks else 0)]
        self.toks = toks
        self.i = 0
        self.no_in = False
        self.depth = 0
        self.match: dict[int, int] = {}
        stack = []
        for k, t in enumerate(toks):
            if t.t == "punc":
                if t.v in "([{":
                    stack.append(k)
                elif t.v in ")]}" and stack:
                    o = stack.pop()
                    if "([{".index(toks[o].v) == ")]}".index(t.v):
                        self.match[o] = k
                    else:
                        stack.clear()

    # ------------------------------------------------------------------ helpers
    @property
    def tok(self) -> Tok:
        return self.toks[self.i]

    def peek(self, k=1) -> Tok:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def is_(self, v, t=None) -> bool:
        tk = self.toks[self.i]
        return tk.v == v and (tk.t in ("punc", "name") if t is None else tk.t == t)

    def eat(self, v) -> bool:
        if self.is_(v):
            self.i += 1
            return True
        return False

    def expect(self, v):
        if not self.eat(v):
            raise ParseError(f"expected {v!r} at {self.tok.pos}")

    def next(self) -> Tok:
        t = self.toks[self.i]
        if t.t != "eof":
            self.i += 1
        return t

    def semi(self):
        self.eat(";")

    # ------------------------------------------------------------------ statements
    def program(self) -> list:
        out = []
        while self.tok.t != "eof":
            if self.is_("}"):
                self.i += 1
                continue
            out.extend(self.stmt_safe())
        return out

    def stmt_safe(self) -> list:
        start = self.i
        try:
            return [self.statement()]
        except (ParseError, RecursionError, IndexError, ValueError, TypeError):
            self.depth = 0
            self.no_in = False
            self.recover(start)
            return []

    def recover(self, start: int):
        if self.i <= start:
            self.i = start
        while self.tok.t != "eof":
            t = self.tok
            if t.t == "punc" and t.v in "([{" and self.i in self.match:
                self.i = self.match[self.i] + 1
                continue
            if t.t == "punc" and t.v == ";":
                self.i += 1
                break
            if t.t == "punc" and t.v == "}":
                break
            if self.i > start and t.nl and t.t == "name" and t.v in STMT_KEYWORDS:
                break
            self.i += 1
        if self.i <= start:
            self.i = start + 1

    def block(self) -> list:
        self.expect("{")
        out = []
        while not self.is_("}") and self.tok.t != "eof":
            out.extend(self.stmt_safe())
        self.expect("}")
        return out

    def statement(self):
        t = self.tok
        pos = t.pos
        if t.t == "punc":
            if t.v == "{":
                return ("block", pos, self.block())
            if t.v == ";":
                self.i += 1
                return ("empty", pos)
        if t.t == "name" and not t.esc:
            v = t.v
            if v in ("var", "const") or (v == "let" and self.peek().t in ("name",) or v == "let" and self.peek().v in ("[", "{")):
                self.i += 1
                d = self.declarations(v)
                self.semi()
                return d
            if v == "function" or (v == "async" and self.peek().v == "function" and not self.peek().nl):
                f = self.function()
                return ("fundecl", pos, f)
            if v == "class":
                return ("classdecl", pos, self.class_())
            if v == "if":
                self.i += 1
                self.expect("(")
                test = self.expression()
                self.expect(")")
                cons = self.statement()
                alt = None
                if self.eat("else"):
                    alt = self.statement()
                return ("if", pos, test, cons, alt)
            if v == "for":
                return self.for_()
            if v == "while":
                self.i += 1
                self.expect("(")
                test = self.expression()
                self.expect(")")
                return ("loop", pos, None, test, None, self.statement())
            if v == "do":
                self.i += 1
                body = self.statement()
                self.expect("while")
                self.expect("(")
                test = self.expression()
                self.expect(")")
                self.semi()
                return ("loop", pos, None, test, None, body)
            if v in ("return", "throw"):
                self.i += 1
                e = None
                if not (self.is_(";") or self.is_("}") or self.tok.t == "eof" or self.tok.nl):
                    e = self.expression()
                self.semi()
                return (v, pos, e)
            if v in ("break", "continue"):
                self.i += 1
                if self.tok.t == "name" and not self.tok.nl:
                    self.i += 1
                self.semi()
                return ("empty", pos)
            if v == "try":
                self.i += 1
                body = self.block()
                param, handler, fin = None, [], []
                if self.eat("catch"):
                    if self.eat("("):
                        param = self.binding()
                        self.expect(")")
                    handler = self.block()
                if self.eat("finally"):
                    fin = self.block()
                return ("try", pos, body, param, handler, fin)
            if v == "switch":
                self.i += 1
                self.expect("(")
                disc = self.expression()
                self.expect(")")
                self.expect("{")
                cases = []
                while not self.is_("}") and self.tok.t != "eof":
                    if self.eat("case"):
                        test = self.expression()
                    else:
                        self.expect("default")
                        test = None
                    self.expect(":")
                    body = []
                    while not (self.is_("case") or self.is_("default") or self.is_("}")) and self.tok.t != "eof":
                        body.extend(self.stmt_safe())
                    cases.append((test, body))
                self.expect("}")
                return ("switch", pos, disc, cases)
            if v == "import" and self.peek().v not in ("(", "."):
                return self.import_()
            if v == "export":
                return self.export_()
            if v == "with":
                self.i += 1
                self.expect("(")
                obj = self.expression()
                self.expect(")")
                return ("block", pos, [("expr", pos, obj), self.statement()])
            if v == "debugger":
                self.i += 1
                self.semi()
                return ("empty", pos)
            if self.peek().v == ":" and self.peek().t == "punc" and v not in ("true", "false", "null", "this"):
                self.i += 2                                   # label
                return self.statement()
        e = self.expression()
        self.semi()
        return ("expr", pos, e)

    def declarations(self, kind):
        pos = self.tok.pos
        decls = []
        while True:
            pat = self.binding()
            init = None
            if self.eat("="):
                init = self.assign()
            decls.append((pat, init))
            if not self.eat(","):
                break
        return ("var", pos, decls)

    def for_(self):
        pos = self.tok.pos
        self.i += 1
        self.eat("await")
        self.expect("(")
        init = None
        if not self.is_(";"):
            self.no_in = True
            try:
                if self.tok.t == "name" and self.tok.v in ("var", "let", "const") and self.peek().v not in ("in", "of", "="):
                    self.i += 1
                    pat = self.binding()
                    if self.tok.v in ("of", "in") and self.tok.t == "name":
                        kind = self.next().v
                        self.no_in = False
                        it = self.assign() if kind == "of" else self.expression()
                        self.expect(")")
                        return ("forof", pos, kind, pat, it, self.statement())
                    decls = []
                    init_v = self.assign() if self.eat("=") else None
                    decls.append((pat, init_v))
                    while self.eat(","):
                        p2 = self.binding()
                        decls.append((p2, self.assign() if self.eat("=") else None))
                    init = ("var", pos, decls)
                else:
                    e = self.expression()
                    if self.tok.v in ("of", "in") and self.tok.t == "name":
                        kind = self.next().v
                        self.no_in = False
                        it = self.assign() if kind == "of" else self.expression()
                        self.expect(")")
                        return ("forof", pos, kind, self.to_pattern(e), it, self.statement())
                    init = ("expr", pos, e)
            finally:
                self.no_in = False
        self.expect(";")
        test = None if self.is_(";") else self.expression()
        self.expect(";")
        update = None if self.is_(")") else self.expression()
        self.expect(")")
        return ("loop", pos, init, test, update, self.statement())

    def import_(self):
        pos = self.tok.pos
        self.i += 1
        specs = []
        if self.tok.t == "str":
            mod = self.next().v
            self.semi()
            return ("import", pos, mod, specs)
        if self.tok.t == "name" and self.tok.v not in ("from",) and not self.is_("{") and not self.is_("*"):
            if self.tok.v == "type" and self.peek().t == "name" and self.peek().v != "from":
                self.i += 1
            specs.append((self.next().v, "default"))
            self.eat(",")
        if self.eat("*"):
            self.expect("as")
            specs.append((self.next().v, "*"))
        if self.eat("{"):
            while not self.is_("}") and self.tok.t != "eof":
                imported = self.next().v
                local = imported
                if self.eat("as"):
                    local = self.next().v
                specs.append((local, imported))
                if not self.eat(","):
                    break
            self.expect("}")
        self.expect("from")
        if self.tok.t != "str":
            raise ParseError("import source")
        mod = self.next().v
        if self.is_("assert") or self.is_("with"):
            self.i += 1
            self.primary()
        self.semi()
        return ("import", pos, mod, specs)

    def export_(self):
        pos = self.tok.pos
        self.i += 1
        if self.eat("default"):
            if self.is_("function") or self.is_("async") and self.peek().v == "function":
                return ("fundecl", pos, self.function())
            if self.is_("class"):
                return ("classdecl", pos, self.class_())
            e = self.assign()
            self.semi()
            return ("expr", pos, e)
        if self.is_("*") or self.is_("{"):
            if self.eat("{"):
                while not self.is_("}") and self.tok.t != "eof":
                    self.i += 1
                self.expect("}")
            else:
                self.i += 1
                if self.eat("as"):
                    self.i += 1
            mod = None
            if self.eat("from"):
                mod = self.next().v
            self.semi()
            return ("import", pos, mod, []) if mod else ("empty", pos)
        return self.statement()

    # ------------------------------------------------------------------ patterns
    def binding(self):
        t = self.tok
        if t.t == "name":
            self.i += 1
            return ("pname", t.v)
        if self.eat("["):
            elems = []
            while not self.is_("]") and self.tok.t != "eof":
                if self.is_(","):
                    self.i += 1
                    elems.append(None)
                    continue
                if self.eat("..."):
                    elems.append(("prest", self.binding()))
                else:
                    b = self.binding()
                    if self.eat("="):
                        b = ("pdef", b, self.assign())
                    elems.append(b)
                if not self.eat(","):
                    break
            self.expect("]")
            return ("parr", elems)
        if self.eat("{"):
            props, rest = [], None
            while not self.is_("}") and self.tok.t != "eof":
                if self.eat("..."):
                    rest = self.binding()
                else:
                    key = self.prop_key()
                    if self.eat(":"):
                        sub = self.binding()
                    else:
                        sub = ("pname", key[2] if key[0] == "str" else "_")
                    if self.eat("="):
                        sub = ("pdef", sub, self.assign())
                    props.append((key, sub))
                if not self.eat(","):
                    break
            self.expect("}")
            return ("pobj", props, rest)
        raise ParseError("binding")

    def to_pattern(self, e):
        k = e[0]
        if k == "name":
            return ("pname", e[2])
        if k == "member":
            return ("pmember", e)
        if k == "arr":
            return ("parr", [None if x is None else (("prest", self.to_pattern(x[2])) if x[0] == "spread"
                                                      else self.to_pattern(x)) for x in e[2]])
        if k == "obj":
            props, rest = [], None
            for kind, key, val in e[2]:
                if kind == "spread":
                    rest = self.to_pattern(key)
                else:
                    props.append((key, self.to_pattern(val)))
            return ("pobj", props, rest)
        if k == "assign" and e[2] == "=":
            return ("pdef", self.to_pattern(e[3]), e[4])
        raise ParseError("pattern")

    # ------------------------------------------------------------------ functions and classes
    def params(self):
        self.expect("(")
        ps = []
        while not self.is_(")") and self.tok.t != "eof":
            if self.eat("..."):
                ps.append(("prest", self.binding()))
            else:
                b = self.binding()
                if self.eat("="):
                    b = ("pdef", b, self.assign())
                ps.append(b)
            if not self.eat(","):
                break
        self.expect(")")
        return ps

    def function(self):
        pos = self.tok.pos
        self.eat("async")
        self.expect("function")
        self.eat("*")
        name = None
        if self.tok.t == "name" and not self.is_("("):
            name = self.next().v
        ps = self.params()
        body = self.block()
        return ("func", pos, name, ps, body, None)

    def arrow(self):
        pos = self.tok.pos
        self.eat("async")
        if self.is_("("):
            ps = self.params()
        else:
            ps = [("pname", self.next().v)]
        self.expect("=>")
        if self.is_("{"):
            return ("func", pos, None, ps, self.block(), None)
        old = self.no_in
        self.no_in = False
        try:
            return ("func", pos, None, ps, None, self.assign())
        finally:
            self.no_in = old

    def is_arrow(self) -> bool:
        t = self.tok
        k = self.i
        if t.t == "name" and t.v == "async" and not self.peek().nl:
            k += 1
            t = self.toks[k]
        if t.t == "name" and t.v not in ("function", "class", "new", "typeof", "void", "delete", "await"):
            nxt = self.toks[min(k + 1, len(self.toks) - 1)]
            return nxt.t == "punc" and nxt.v == "=>"
        if t.t == "punc" and t.v == "(" and k in self.match:
            j = self.match[k] + 1
            return j < len(self.toks) and self.toks[j].t == "punc" and self.toks[j].v == "=>"
        return False

    def class_(self):
        pos = self.tok.pos
        self.expect("class")
        name = None
        if self.tok.t == "name" and self.tok.v != "extends" and not self.is_("{"):
            name = self.next().v
        sup = None
        if self.eat("extends"):
            sup = self.lhs()
        self.expect("{")
        methods, fields = [], []
        while not self.is_("}") and self.tok.t != "eof":
            if self.eat(";"):
                continue
            if self.is_("static") and self.peek().v == "{":
                self.i += 1
                methods.append(("func", self.tok.pos, "static", [], self.block(), None))
                continue
            while self.tok.t == "name" and self.tok.v in ("static", "async", "get", "set") and \
                    self.peek().v not in ("(", "=", ";", "}"):
                self.i += 1
            self.eat("*")
            self.eat("#")
            mpos = self.tok.pos
            key = self.prop_key()
            if self.is_("("):
                ps = self.params()
                body = self.block()
                mname = key[2] if key[0] == "str" else None
                methods.append(("func", mpos, mname, ps, body, None))
            else:
                if self.eat("="):
                    fields.append(self.assign())
                self.semi()
        self.expect("}")
        return ("class", pos, name, sup, methods, fields)

    # ------------------------------------------------------------------ expressions
    def expression(self):
        pos = self.tok.pos
        e = self.assign()
        if self.is_(","):
            seq = [e]
            while self.eat(","):
                seq.append(self.assign())
            return ("seq", pos, seq)
        return e

    def assign(self):
        self.depth += 1
        if self.depth > MAX_PARSE_DEPTH:
            raise ParseError("too deep")
        try:
            if self.is_arrow():
                return self.arrow()
            pos = self.tok.pos
            if self.is_("yield", "name"):
                self.i += 1
                self.eat("*")
                if self.is_(")") or self.is_("]") or self.is_("}") or self.is_(",") or self.is_(";") or self.tok.nl:
                    return ("lit", pos, UNDEF)
                return ("unary", pos, "await", self.assign())
            left = self.conditional()
            t = self.tok
            if t.t == "punc" and t.v in ASSIGN:
                self.i += 1
                right = self.assign()
                if t.v == "=" and left[0] in ("arr", "obj"):
                    return ("destruct", pos, self.to_pattern(left), right)
                return ("assign", pos, t.v, left, right)
            return left
        finally:
            self.depth -= 1

    def conditional(self):
        pos = self.tok.pos
        test = self.binary(0)
        if self.is_("?", None) and self.tok.t == "punc":
            self.i += 1
            old = self.no_in
            self.no_in = False
            a = self.assign()
            self.no_in = old
            self.expect(":")
            b = self.assign()
            return ("cond", pos, test, a, b)
        return test

    def binary(self, min_prec):
        left = self.unary()
        while True:
            t = self.tok
            if t.t == "punc" or (t.t == "name" and t.v in ("instanceof", "in")):
                op = t.v
            else:
                break
            if op == "in" and self.no_in:
                break
            p = BINARY.get(op)
            if p is None or p < min_prec:
                break
            self.i += 1
            right = self.binary(p if op == "**" else p + 1)
            left = ("logic" if op in ("&&", "||", "??") else "bin", t.pos, op, left, right)
        return left

    def unary(self):
        t = self.tok
        if (t.t == "punc" and t.v in ("!", "~", "+", "-", "++", "--")) or \
                (t.t == "name" and t.v in ("typeof", "void", "delete", "await") and not t.esc and
                 not (self.peek().t == "punc" and self.peek().v in (")", ";", ",", "=", "]", "}", ".", "=>"))):
            self.i += 1
            self.depth += 1
            if self.depth > MAX_PARSE_DEPTH:
                raise ParseError("too deep")
            try:
                return ("unary", t.pos, t.v, self.unary())
            finally:
                self.depth -= 1
        e = self.lhs()
        if self.tok.t == "punc" and self.tok.v in ("++", "--") and not self.tok.nl:
            self.i += 1
            return ("update", t.pos, e)
        return e

    def args(self):
        self.expect("(")
        out = []
        old = self.no_in
        self.no_in = False
        while not self.is_(")") and self.tok.t != "eof":
            if self.eat("..."):
                out.append(("spread", self.tok.pos, self.assign()))
            else:
                out.append(self.assign())
            if not self.eat(","):
                break
        self.no_in = old
        self.expect(")")
        return out

    def lhs(self, no_call=False):
        t = self.tok
        if t.t == "name" and t.v == "new" and not t.esc:
            self.i += 1
            if self.eat("."):
                self.next()
                e = ("lit", t.pos, UNDEF)
            else:
                callee = self.lhs(no_call=True)
                a = self.args() if self.is_("(") else []
                e = ("new", t.pos, callee, a)
        else:
            e = self.primary()
        while True:
            t = self.tok
            if t.t == "punc" and t.v in (".", "?."):
                self.i += 1
                if t.v == "?." and self.is_("("):
                    if no_call:
                        break
                    e = ("call", t.pos, e, self.args())
                    continue
                if t.v == "?." and self.is_("["):
                    self.i += 1
                    k = self.expression()
                    self.expect("]")
                    e = ("member", t.pos, e, k, True)
                    continue
                self.eat("#")
                nt = self.next()
                if nt.t != "name":
                    raise ParseError("member name")
                e = ("member", t.pos, e, ("str", nt.pos, nt.v, nt.esc), False)
            elif t.t == "punc" and t.v == "[":
                self.i += 1
                old = self.no_in
                self.no_in = False
                k = self.expression()
                self.no_in = old
                self.expect("]")
                e = ("member", t.pos, e, k, True)
            elif t.t == "punc" and t.v == "(" and not no_call:
                e = ("call", t.pos, e, self.args())
            elif t.t == "tmpl" and not no_call:
                e = ("call", t.pos, e, [self.primary()])
            elif t.t == "punc" and t.v == "!" and not t.nl and self.peek().v in (".", "[", "(", ")", ";", ","):
                self.i += 1                                           # TypeScript non-null (in .js? rare) - ignore
            else:
                break
        return e

    def prop_key(self):
        t = self.tok
        if t.t in ("name", "str"):
            self.i += 1
            return ("str", t.pos, t.v, t.esc)
        if t.t == "num":
            self.i += 1
            return ("str", t.pos, _num_str(t.v), False)
        if self.eat("["):
            k = self.assign()
            self.expect("]")
            return k
        raise ParseError("property key")

    def primary(self):
        t = self.tok
        pos = t.pos
        if t.t == "num":
            self.i += 1
            return ("lit", pos, t.v)
        if t.t == "str":
            self.i += 1
            return ("str", pos, t.v, t.esc)
        if t.t == "regex":
            self.i += 1
            return ("regex", pos, t.v[0], t.v[1])
        if t.t == "tmpl":
            self.i += 1
            parts, exprs = t.v
            nodes = []
            for toks in exprs:
                sub = Parser(toks)
                try:
                    nodes.append(sub.expression() if sub.tok.t != "eof" else ("lit", pos, ""))
                except (ParseError, RecursionError, IndexError):
                    nodes.append(("unknown", pos))
            return ("tmpl", pos, parts, nodes)
        if t.t == "punc":
            if t.v == "(":
                self.i += 1
                old = self.no_in
                self.no_in = False
                e = self.expression()
                self.no_in = old
                self.expect(")")
                return ("paren", pos, e)
            if t.v == "[":
                self.i += 1
                elems = []
                while not self.is_("]") and self.tok.t != "eof":
                    if self.is_(","):
                        self.i += 1
                        elems.append(("lit", pos, UNDEF))
                        continue
                    if self.eat("..."):
                        elems.append(("spread", self.tok.pos, self.assign()))
                    else:
                        elems.append(self.assign())
                    if not self.eat(","):
                        break
                self.expect("]")
                return ("arr", pos, elems)
            if t.v == "{":
                return self.object()
            if t.v == "#":
                self.i += 1
                return self.primary()
            raise ParseError(f"unexpected {t.v!r}")
        if t.t == "name":
            v = t.v
            if not t.esc:
                if v == "function" or (v == "async" and self.peek().v == "function" and not self.peek().nl):
                    return self.function()
                if v == "class":
                    return self.class_()
                if v == "this":
                    self.i += 1
                    return ("this", pos)
                if v in ("true", "false", "null"):
                    self.i += 1
                    return ("lit", pos, {"true": True, "false": False, "null": None}[v])
                if v == "import":
                    self.i += 1
                    if self.eat("."):
                        self.next()
                        return ("lit", pos, UNDEF)
                    return ("call", pos, ("name", pos, "import", False), self.args())
                if v in STMT_KEYWORDS - {"function", "class", "import"}:
                    raise ParseError(f"keyword {v}")
            self.i += 1
            return ("name", pos, v, t.esc)
        raise ParseError("unexpected end")

    def object(self):
        pos = self.tok.pos
        self.expect("{")
        props = []
        old = self.no_in
        self.no_in = False
        while not self.is_("}") and self.tok.t != "eof":
            if self.eat("..."):
                props.append(("spread", self.assign(), None))
            else:
                while self.tok.t == "name" and self.tok.v in ("async", "get", "set") and \
                        self.peek().v not in (",", ":", "(", "}", "="):
                    self.i += 1
                self.eat("*")
                kt = self.tok
                key = self.prop_key()
                if self.eat(":"):
                    props.append(("kv", key, self.assign()))
                elif self.is_("("):
                    ps = self.params()
                    body = self.block()
                    props.append(("kv", key, ("func", kt.pos, key[2] if key[0] == "str" else None, ps, body, None)))
                else:
                    val = ("name", kt.pos, kt.v, kt.esc)
                    if self.eat("="):
                        val = ("assign", kt.pos, "=", val, self.assign())
                    props.append(("kv", key, val))
            if not self.eat(","):
                break
        self.no_in = old
        self.expect("}")
        return ("obj", pos, props)


def _num_str(n) -> str:
    if isinstance(n, bool):
        return "true" if n else "false"
    if isinstance(n, int):
        return str(n)
    if isinstance(n, float):
        if n != n:
            return "NaN"
        if n in (float("inf"), float("-inf")):
            return "Infinity" if n > 0 else "-Infinity"
        if n.is_integer() and abs(n) < 1e21:
            return str(int(n))
        return repr(n)
    return str(n)


def parse(text: str, deadline_check=None) -> list:
    toks, _ = lex(text, 0, False, deadline_check)
    return Parser(toks).program()


# =========================================================================================================== evaluator

class Func:
    __slots__ = ("node", "scope", "name", "calls")

    def __init__(self, node, scope):
        self.node, self.scope, self.name, self.calls = node, scope, node[2], 0


class Scope:
    __slots__ = ("vars", "parent")

    def __init__(self, parent=None):
        self.vars: dict = {}
        self.parent = parent

    def lookup(self, name):
        s = self
        while s is not None:
            if name in s.vars:
                return s.vars[name]
            s = s.parent
        return None

    def assign(self, name, v):
        s = self
        while s is not None:
            if name in s.vars:
                s.vars[name] = v
                return
            if s.parent is None:
                s.vars[name] = v
                return
            s = s.parent


GLOBAL_NAMES = {"require", "eval", "Function", "process", "Buffer", "atob", "btoa", "String", "Array", "Object", "JSON",
                "Math", "Number", "parseInt", "parseFloat", "decodeURIComponent", "decodeURI", "unescape", "escape",
                "encodeURIComponent", "encodeURI", "fetch", "setTimeout", "setInterval", "setImmediate", "queueMicrotask",
                "Promise", "Reflect", "console", "module", "exports", "Date", "RegExp", "Symbol", "Error", "WebSocket",
                "XMLHttpRequest", "TextDecoder", "TextEncoder", "URL", "URLSearchParams", "Boolean", "Uint8Array",
                "import", "navigator", "location", "document"}
GLOBAL_OBJECTS = {"global", "globalThis", "window", "self", "GLOBAL", "root"}
ALIASES = {"process.mainModule.require": "require", "module.require": "require", "Function.prototype.constructor": "Function",
           "fs.promises": "fs.promises", "process.mainModule.constructor._load": "require",
           "module.constructor._load": "require", "Reflect.construct": "Reflect.construct"}
EXEC_REFS = {"eval", "Function", "vm.runInNewContext", "vm.runInThisContext", "vm.runInContext", "vm.Script",
             "vm.compileFunction", "vm.SourceTextModule"}
PROC_METHODS = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
HTTP_MODS = {"http", "https", "http2"}
CLIENT_MODS = {"axios", "node-fetch", "got", "request", "undici", "superagent", "needle", "cross-fetch", "isomorphic-fetch",
               "phin", "bent"}
SEND_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "fetch", "options"}
ENV_HOME = {"HOME": "~", "USERPROFILE": "~", "HOMEPATH": "~", "APPDATA": "~/appdata/roaming",
            "LOCALAPPDATA": "~/appdata/local"}
ENV_SYSINFO = {"USER", "USERNAME", "LOGNAME", "COMPUTERNAME", "HOSTNAME", "USERDOMAIN", "PWD", "INIT_CWD"}
SHELL_PROGS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh",
               "/bin/sh", "/bin/bash", "/bin/zsh"}


def _meta(v: Val, k, default=None):
    m = v.meta
    return m.get(k, default) if isinstance(m, dict) else default


def _with_meta(v: Val, **kw) -> Val:
    m = dict(v.meta) if isinstance(v.meta, dict) else {}
    m.update(kw)
    return Val(v.c, v.tags, v.ref, m)


def _tags(*vals, depth=0) -> frozenset:
    """Tags of the values and of what they hold (arrays, objects: a few levels deep)."""
    out = set()
    for v in vals:
        if isinstance(v, Val):
            out |= v.tags
            if depth < 3:
                if isinstance(v.c, list):
                    out |= _tags(*v.c[:200], depth=depth + 1)
                elif isinstance(v.c, dict):
                    out |= _tags(*list(v.c.values())[:200], depth=depth + 1)
    return frozenset(out)


def _mod(name: str) -> str:
    n = name[5:] if name.startswith("node:") else name
    return {"fs/promises": "fs.promises", "dns/promises": "dns.promises", "timers/promises": "timers"}.get(n, n)


def _func_val(f: Func) -> Val:
    return Val(NOVAL, (), None, {"fn": f})


class Analyzer:
    def __init__(self, ctx, text: str, file: str, phase: str, depth: int = 0, line_base=None, scope=None):
        self.ctx, self.text, self.file, self.depth, self.line_base = ctx, text, file, depth, line_base
        self.pol = ctx.pol
        lim = ctx.limits
        self.max_string = int(lim["max_string"])
        self.max_iter = int(lim["max_iter"])
        self.max_steps = int(lim["max_steps"])
        self.call_depth_limit = 2 * int(lim["max_depth"])
        self.phase = phase
        self.base_phase = phase
        self.steps = 0
        self.iters = 0
        self.stack: list = []
        self.returns: list = []
        self.funcs: list[Func] = []
        self.reached: set = set()                  # id(func node) evaluated at least once
        self.nl = [i for i, c in enumerate(text) if c == "\n"] if line_base is None else []
        rel_dir = file.rsplit("/", 1)[0] if "/" in file else "."
        self.globals = scope or Scope()
        self.cur_scope = self.globals
        if scope is None:
            self.globals.vars.update({"__dirname": Val(rel_dir), "__filename": Val(file)})

    # ---------------------------------------------------------------- bookkeeping
    def step(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise LimitExceeded("step limit")
        if self.steps % 2000 == 0:
            self.ctx.check_time()

    def line(self, pos) -> int:
        if self.line_base is not None:
            return int(self.line_base or 1)
        return bisect.bisect_right(self.nl, pos) + 1 if pos is not None else 1

    def emit(self, finding, node_pos, detail=None):
        if detail is None:
            if self.line_base is not None:
                detail = self.text[:160]
            else:
                start = self.text.rfind("\n", 0, node_pos) + 1
                if node_pos - start > 80:
                    start = node_pos - 40
                end = self.text.find("\n", node_pos)
                end = len(self.text) if end < 0 else min(end, start + 200)
                detail = self.text[start:end]
        self.ctx.emit(finding, self.phase, self.file, self.line(node_pos), detail)

    @property
    def auto(self) -> bool:
        return self.phase in self.pol.auto

    def mk(self, c, tags=frozenset(), **meta) -> Val:
        if isinstance(c, (str, bytes, bytearray)) and len(c) > self.max_string:
            return Val(NOVAL, tags)
        if isinstance(c, list) and len(c) > self.max_iter:
            return Val(NOVAL, _tags(*c[:100]) | frozenset(tags))
        return Val(c, tags, None, meta or None)

    # ---------------------------------------------------------------- program
    def run(self, stmts):
        self.hoist(stmts, self.globals)
        self.exec_list(stmts, self.globals)
        # functions nothing at this phase reached: analyzed as "call" with unknown arguments
        self.phase = "call"
        k = 0
        while k < len(self.funcs):
            f = self.funcs[k]
            k += 1
            if id(f.node) in self.reached:
                continue
            self.invoke(f, [], None, leftover=True)

    def hoist(self, stmts, scope):
        for s in stmts:
            if s[0] == "fundecl" and s[2][2]:
                scope.vars[s[2][2]] = self.make_func(s[2], scope)
            elif s[0] == "classdecl" and s[2][2]:
                scope.vars.setdefault(s[2][2], UNKNOWN)

    def make_func(self, node, scope) -> Val:
        f = Func(node, scope)
        self.funcs.append(f)
        return _func_val(f)

    def exec_list(self, stmts, scope):
        for s in stmts:
            try:
                self.exec(s, scope)
            except LimitExceeded:
                raise
            except RecursionError:
                continue
            except Exception:                          # noqa: BLE001 - a statement we cannot follow is skipped
                continue

    def exec(self, s, scope):
        self.step()
        k = s[0]
        if k == "expr":
            self.ev(s[2], scope)
        elif k == "var":
            for pat, init in s[2]:
                v = self.ev(init, scope) if init is not None else Val(UNDEF)
                self.bind(pat, v, scope, declare=True)
        elif k == "block":
            self.hoist(s[2], scope)
            self.exec_list(s[2], scope)
        elif k == "if":
            self.ev(s[2], scope)
            self.exec(s[3], scope)
            if s[4] is not None:
                self.exec(s[4], scope)
        elif k == "loop":
            if s[2] is not None:
                self.exec(s[2], scope)
            if s[3] is not None:
                self.ev(s[3], scope)
            self.exec(s[5], scope)
            if s[4] is not None:
                self.ev(s[4], scope)
        elif k == "forof":
            it = self.ev(s[4], scope)
            items = None
            if s[2] == "of":
                if isinstance(it.c, list):
                    items = it.c
                elif isinstance(it.c, str) and len(it.c) <= 1000:
                    items = [Val(ch, it.tags) for ch in it.c]
            elif isinstance(it.c, dict):
                items = [Val(key) for key in it.c]
            if items is not None and len(items) and self.iters + len(items) <= self.max_iter and len(items) <= 64:
                self.iters += len(items)
                for item in items:
                    self.bind(s[3], item, scope, declare=True)
                    self.exec(s[5], scope)
            else:
                self.bind(s[3], Val(NOVAL, _tags(it)), scope, declare=True)
                self.exec(s[5], scope)
        elif k in ("return", "throw"):
            v = self.ev(s[2], scope) if s[2] is not None else Val(UNDEF)
            if k == "return" and self.returns:
                self.returns[-1].append(v)
        elif k == "try":
            self.hoist(s[2], scope)
            self.exec_list(s[2], scope)
            if s[3] is not None:
                self.bind(s[3], UNKNOWN, scope, declare=True)
            self.hoist(s[4], scope)
            self.exec_list(s[4], scope)
            self.hoist(s[5], scope)
            self.exec_list(s[5], scope)
        elif k == "switch":
            self.ev(s[2], scope)
            for test, body in s[3]:
                if test is not None:
                    self.ev(test, scope)
                self.hoist(body, scope)
                self.exec_list(body, scope)
        elif k == "classdecl":
            v = self.ev(s[2], scope)
            if s[2][2]:
                scope.vars[s[2][2]] = v
        elif k == "import":
            if s[2] is None:
                return
            mod = self.require(Val(s[2]), s[1])
            for local, imported in s[3]:
                if imported in ("default", "*"):
                    scope.vars[local] = mod
                else:
                    scope.vars[local] = self.member(mod, imported, False, s[1])
        # fundecl: hoisted; empty: nothing

    # ---------------------------------------------------------------- binding
    def bind(self, pat, v, scope, declare=False):
        k = pat[0]
        if k == "pname":
            if declare:
                scope.vars[pat[1]] = v
            else:
                scope.assign(pat[1], v)
        elif k == "pdef":
            if v.c is UNDEF:
                v = self.ev(pat[2], scope)
            self.bind(pat[1], v, scope, declare)
        elif k == "parr":
            items = v.c if isinstance(v.c, list) else None
            for i, sub in enumerate(pat[1]):
                if sub is None:
                    continue
                if sub[0] == "prest":
                    rest = self.mk(items[i:]) if items is not None else Val(NOVAL, _tags(v))
                    self.bind(sub[1], rest, scope, declare)
                    break
                item = (items[i] if i < len(items) else Val(UNDEF)) if items is not None else Val(NOVAL, _tags(v))
                self.bind(sub, item, scope, declare)
        elif k == "pobj":
            for key, sub in pat[1]:
                kv = self.ev(key, scope) if key[0] != "str" else Val(key[2])
                name = kv.c if isinstance(kv.c, str) else None
                item = self.member(v, name, False, 0) if name is not None else Val(NOVAL, _tags(v))
                self.bind(sub, item, scope, declare)
            if pat[2] is not None:
                self.bind(pat[2], Val(NOVAL, _tags(v)), scope, declare)
        elif k == "prest":
            self.bind(pat[1], v, scope, declare)
        elif k == "pmember":
            self.assign_to(pat[1], v, scope)

    def assign_to(self, target, v, scope):
        k = target[0]
        if k == "name":
            scope.assign(target[2], v)
        elif k == "member":
            obj = self.ev(target[2], scope)
            key = self.key_of(target, scope)[0]
            if isinstance(obj.c, dict) and isinstance(key, str):
                if len(obj.c) < 10000:
                    obj.c[key] = v
            elif isinstance(obj.c, list) and isinstance(key, (int, float)) and 0 <= int(key) < len(obj.c) + 1 \
                    and len(obj.c) < self.max_iter:
                key = int(key)
                if key == len(obj.c):
                    obj.c.append(v)
                else:
                    obj.c[key] = v
            elif obj.ref in GLOBAL_OBJECTS or obj.ref == "global":
                if isinstance(key, str):
                    self.globals.vars[key] = v
        elif k in ("paren",):
            self.assign_to(target[2], v, scope)

    # ---------------------------------------------------------------- expressions
    def ev(self, n, scope) -> Val:
        if n is None:
            return Val(UNDEF)
        self.step()
        k = n[0]
        try:
            fn = getattr(self, "e_" + k)
        except AttributeError:
            return UNKNOWN
        return fn(n, scope)

    def e_lit(self, n, scope):
        return Val(n[2])

    def e_str(self, n, scope):
        return self.mk(n[2])

    def e_unknown(self, n, scope):
        return UNKNOWN

    def e_regex(self, n, scope):
        return Val(NOVAL, (), None, {"regex": (n[2], n[3])})

    def e_paren(self, n, scope):
        return self.ev(n[2], scope)

    def e_this(self, n, scope):
        v = scope.lookup("this")
        return v if v is not None else UNKNOWN

    def e_seq(self, n, scope):
        v = UNKNOWN
        for x in n[2]:
            v = self.ev(x, scope)
        return v

    def e_name(self, n, scope):
        name = n[2]
        v = scope.lookup(name)
        if v is not None:
            if n[3] and v.ref:
                return _with_meta(v, hidden=True)
            return v
        if name in GLOBAL_OBJECTS:
            return Val(NOVAL, (), "global")
        if name in GLOBAL_NAMES:
            return Val(NOVAL, (), name, {"hidden": True} if n[3] else None)
        if name == "undefined":
            return Val(UNDEF)
        if name in ("NaN", "Infinity"):
            return Val(float("nan") if name == "NaN" else float("inf"))
        return UNKNOWN

    def e_tmpl(self, n, scope):
        parts = []
        for i, s in enumerate(n[2]):
            parts.append(Val(s))
            if i < len(n[3]):
                parts.append(self.ev(n[3][i], scope))
        return self.concat(parts)

    def e_arr(self, n, scope):
        out = []
        for e in n[2]:
            if e[0] == "spread":
                v = self.ev(e[2], scope)
                if isinstance(v.c, list):
                    out.extend(v.c)
                elif isinstance(v.c, str):
                    out.extend(Val(ch, v.tags) for ch in v.c[:10000])
                else:
                    return Val(NOVAL, _tags(v, *out))
            else:
                out.append(self.ev(e, scope))
            if len(out) > self.max_iter:
                return Val(NOVAL, _tags(*out[:100]))
        return Val(out)

    def e_obj(self, n, scope):
        out = {}
        tags = set()
        for kind, key, val in n[2]:
            if kind == "spread":
                v = self.ev(key, scope)
                if isinstance(v.c, dict):
                    out.update(v.c)
                else:
                    tags |= _tags(v)
                continue
            kv = Val(key[2]) if key[0] == "str" else self.ev(key, scope)
            name = kv.c if isinstance(kv.c, str) else (_num_str(kv.c) if isinstance(kv.c, (int, float)) else None)
            v = self.ev(val, scope)
            if name is not None:
                out[name] = v
            else:
                tags |= _tags(v)
        return Val(out, tags)

    def e_func(self, n, scope):
        return self.make_func(n, scope)

    def e_class(self, n, scope):
        ctor = None
        methods = {}
        for m in n[4]:
            fv = self.make_func(m, scope)
            if m[2] == "constructor":
                ctor = fv
            elif m[2]:
                methods[m[2]] = fv
        for fexpr in n[5]:
            self.ev(fexpr, scope)
        sup = self.ev(n[3], scope) if n[3] is not None else None
        return Val(NOVAL, (), None, {"cls": ctor, "methods": methods, "sup": sup})

    def e_spread(self, n, scope):
        return self.ev(n[2], scope)

    def e_cond(self, n, scope):
        t = self.ev(n[2], scope)
        if t.known and t.c is not NOVAL and not isinstance(t.c, (list, dict)):
            return self.ev(n[3] if _truthy(t.c) else n[4], scope)
        a = self.ev(n[3], scope)
        b = self.ev(n[4], scope)
        return self.alts(a, b)

    def alts(self, a: Val, b: Val) -> Val:
        if a.known and b.known and type(a.c) is type(b.c) and not isinstance(a.c, (list, dict)) and a.c == b.c:
            return Val(a.c, a.tags | b.tags)
        if a.ref and a.ref == b.ref:
            return a
        al = (_meta(a, "alts") or [a]) + (_meta(b, "alts") or [b])
        return Val(NOVAL, _tags(a, b), None, {"alts": al[:6]})

    def e_logic(self, n, scope):
        a = self.ev(n[3], scope)
        op = n[2]
        if a.known and not isinstance(a.c, (list, dict)):
            if op == "||":
                return a if _truthy(a.c) else self.ev(n[4], scope)
            if op == "&&":
                return self.ev(n[4], scope) if _truthy(a.c) else a
            return a if a.c not in (None,) and a.c is not UNDEF else self.ev(n[4], scope)
        if op == "&&":
            b = self.ev(n[4], scope)
            return Val(b.c, b.tags | a.tags, b.ref, b.meta)
        if a.known or a.ref or _meta(a, "fn") or _meta(a, "obj"):
            self.ev(n[4], scope)
            return a
        return self.alts(a, self.ev(n[4], scope))

    def e_unary(self, n, scope):
        op = n[2]
        v = self.ev(n[3], scope)
        if op == "await":
            if _meta(v, "promise") is not None:
                return _meta(v, "promise")
            return v
        if op == "typeof":
            return Val(NOVAL)
        if op in ("void", "delete"):
            return Val(UNDEF)
        if not v.known:
            return Val(NOVAL, v.tags)
        c = v.c
        try:
            if op == "!":
                return Val(not _truthy(c))
            num = _to_num(c)
            if num is None:
                return Val(NOVAL, v.tags)
            if op == "-":
                return Val(-num, v.tags)
            if op == "+":
                return Val(num, v.tags)
            if op == "~":
                return Val(~_int32(num), v.tags)
            if op in ("++", "--"):
                r = num + (1 if op == "++" else -1)
                if n[3][0] in ("name", "member"):
                    self.assign_to(n[3], Val(r), scope)
                return Val(r)
        except (TypeError, ValueError, OverflowError):
            pass
        return Val(NOVAL, v.tags)

    def e_update(self, n, scope):
        v = self.ev(n[2], scope)
        num = _to_num(v.c) if v.known else None
        if num is not None and n[2][0] in ("name", "member"):
            self.assign_to(n[2], Val(num + 1), scope)
        return v

    def e_bin(self, n, scope):
        return self.binop(n[2], self.ev(n[3], scope), self.ev(n[4], scope))

    def e_assign(self, n, scope):
        op = n[2]
        target = n[3]
        if op == "=":
            v = self.ev(n[4], scope)
        else:
            cur = self.ev(target, scope)
            if op in ("||=", "&&=", "??="):
                v = self.e_logic(("logic", n[1], op[:-1], ("lit", n[1], cur.c) if cur.known else target, n[4]), scope)
            else:
                v = self.binop(op[:-1], cur, self.ev(n[4], scope))
        if target[0] in ("name", "member", "paren"):
            self.assign_to(target, v, scope)
        return v

    def e_destruct(self, n, scope):
        v = self.ev(n[3], scope)
        self.bind(n[2], v, scope)
        return v

    def binop(self, op, a: Val, b: Val) -> Val:
        if op == "+":
            if a.known and b.known and not (_is_strish(a.c) or _is_strish(b.c)):
                x, y = _to_num(a.c), _to_num(b.c)
                if x is not None and y is not None:
                    return Val(x + y, a.tags | b.tags)
            return self.concat([a, b])
        if not (a.known and b.known):
            return Val(NOVAL, _tags(a, b))
        x, y = a.c, b.c
        tags = a.tags | b.tags
        try:
            if op in ("===", "==", "!==", "!="):
                eq = _js_eq(x, y)
                return Val(eq if op in ("===", "==") else not eq)
            if op in ("<", ">", "<=", ">=") and isinstance(x, str) and isinstance(y, str):
                return Val({"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op])
            if op in ("in", "instanceof"):
                return Val(NOVAL)
            xn, yn = _to_num(x), _to_num(y)
            if xn is None or yn is None:
                return Val(NOVAL, tags)
            if op == "-":
                return Val(xn - yn, tags)
            if op == "*":
                return Val(xn * yn, tags)
            if op == "/":
                return Val(xn / yn if yn else float("nan"), tags)
            if op == "%":
                return Val(_js_mod(xn, yn), tags)
            if op == "**":
                if abs(yn) > 1024 or abs(xn) > 1e15:
                    return Val(NOVAL, tags)
                return Val(xn ** yn, tags)
            if op in ("<", ">", "<=", ">="):
                return Val({"<": xn < yn, ">": xn > yn, "<=": xn <= yn, ">=": xn >= yn}[op])
            xi, yi = _int32(xn), _int32(yn)
            if op == "&":
                return Val(_int32(xi & yi), tags)
            if op == "|":
                return Val(_int32(xi | yi), tags)
            if op == "^":
                return Val(_int32(xi ^ yi), tags)
            if op == "<<":
                return Val(_int32(xi << (yi & 31)), tags)
            if op == ">>":
                return Val(xi >> (yi & 31), tags)
            if op == ">>>":
                return Val((xi & 0xFFFFFFFF) >> (yi & 31), tags)
        except (TypeError, ValueError, OverflowError, ZeroDivisionError):
            pass
        return Val(NOVAL, tags)

    def concat(self, parts: list) -> Val:
        """String concatenation; an unknown part keeps the known text around it as a hint (`partial`) for the path and
        address classifiers, and marks credential / autostart paths built that way."""
        tags = _tags(*parts)
        texts = []
        known = True
        for p in parts:
            s = _to_str(p.c) if p.known else None
            if s is None:
                known = False
                s = _meta(p, "partial") or PH
            texts.append(s)
        total = sum(len(t) for t in texts)
        if known:
            if total > self.max_string:
                return Val(NOVAL, tags)
            return Val("".join(texts), tags)
        hint = "".join(texts)[:600]
        return Val(NOVAL, tags | _path_tags(hint), None, {"partial": hint})

    # ---------------------------------------------------------------- member access
    def key_of(self, n, scope):
        """(key, hidden) of a member node: hidden when the name was computed or written with escapes."""
        k = n[3]
        if not n[4]:
            return k[2], bool(k[3])
        if k[0] == "str":
            return k[2], bool(k[3])
        v = self.ev(k, scope)
        if isinstance(v.c, str):
            return v.c, True
        if isinstance(v.c, (int, float)) and not isinstance(v.c, bool):
            return (int(v.c) if float(v.c).is_integer() else v.c), False
        return None, True

    def e_member(self, n, scope):
        obj = self.ev(n[2], scope)
        key, hidden = self.key_of(n, scope)
        return self.member(obj, key, hidden, n[1])

    def member(self, obj: Val, key, hidden, pos) -> Val:
        hidden = hidden or bool(_meta(obj, "hidden"))
        if key is None:
            return Val(NOVAL, _tags(obj))
        if obj.ref:
            ref = obj.ref
            if ref == "global":
                if isinstance(key, str):
                    v = self.globals.vars.get(key)
                    if v is not None:
                        return v
                    if key in GLOBAL_OBJECTS:
                        return obj
                    return Val(NOVAL, (), key, {"hidden": True} if hidden else None)
            if ref == "process.env":
                return self.env_var(key)
            if ref == "process" and key in ("execPath", "argv0"):
                return Val("node")
            if not isinstance(key, str):
                return Val(NOVAL, obj.tags)
            full = ALIASES.get(f"{ref}.{key}", f"{ref}.{key}")
            if full == "process.env":
                return Val(NOVAL, frozenset({SECRET}), "process.env")
            return Val(NOVAL, obj.tags, full, {"hidden": True} if hidden else None)
        f = _meta(obj, "fn")
        if f is not None or _meta(obj, "cls") is not None:
            if key == "constructor":
                return Val(NOVAL, (), "Function", {"hidden": True} if hidden else None)
            if key in ("call", "apply", "bind"):
                return Val(NOVAL, (), None, {"bound": (obj, key)})
            methods = _meta(obj, "methods") or {}
            if key in methods:
                return methods[key]
            return Val(NOVAL, obj.tags)
        c = obj.c
        if isinstance(c, dict):
            if key in c:
                return c[key]
            if key == "constructor":
                return Val(NOVAL, (), "Object")
            return Val(NOVAL, obj.tags, None, {"recv": obj, "name": key})
        if isinstance(c, (list, str, bytes, bytearray)):
            if key == "length":
                return Val(len(c), obj.tags)
            if isinstance(key, int) and 0 <= key < len(c):
                if isinstance(c, list):
                    return c[key]
                if isinstance(c, str):
                    return Val(c[key], obj.tags)
                return Val(c[key], obj.tags)
            if key == "constructor":
                return Val(NOVAL, (), "String" if isinstance(c, str) else "Array")
            return Val(NOVAL, obj.tags, None, {"recv": obj, "name": key})
        kind = _meta(obj, "obj")
        if kind in ("child",) and key in ("stdout", "stderr", "stdin"):
            return Val(NOVAL, obj.tags, None, {"obj": "childio", "child": obj, "io": key})
        if kind == "res":
            return Val(NOVAL, obj.tags | {NET})
        return Val(NOVAL, obj.tags - {CRED_PATH, AUTOSTART_PATH}, None, {"recv": obj, "name": key})

    def env_var(self, key) -> Val:
        if not isinstance(key, str):
            return Val(NOVAL, frozenset({SECRET_ENV}))      # process.env[name]: one variable, name unknown
        if key in ENV_HOME:
            return Val(ENV_HOME[key])
        if key in ENV_SYSINFO:
            return Val(NOVAL, frozenset({SYSINFO}))
        if is_secret_env(key):
            return Val(NOVAL, frozenset({SECRET_ENV}))
        return Val(NOVAL, frozenset({ENV}))

    # ---------------------------------------------------------------- calls
    def e_new(self, n, scope):
        callee = self.ev(n[2], scope)
        args = self.eval_args(n[3], scope)
        cls = _meta(callee, "cls")
        if cls is not None or _meta(callee, "methods") is not None:
            inst = Val(dict(_meta(callee, "methods") or {}))
            if cls is not None:
                self.invoke(_meta(cls, "fn"), args, inst)
            return inst
        return self.apply(callee, args, None, n, new=True)

    def e_call(self, n, scope):
        callee_node = n[2]
        recv = None
        if callee_node[0] == "member":
            recv = self.ev(callee_node[2], scope)
            key, hidden = self.key_of(callee_node, scope)
            fnv = self.member(recv, key, hidden, callee_node[1])
        else:
            fnv = self.ev(callee_node, scope)
            if callee_node[0] == "paren" and callee_node[2][0] == "seq" and fnv.ref == "eval":
                fnv = _with_meta(fnv, indirect=True)
        args = self.eval_args(n[3], scope)
        return self.apply(fnv, args, recv, n)

    def eval_args(self, nodes, scope) -> list:
        out = []
        for a in nodes:
            if a[0] == "spread":
                v = self.ev(a[2], scope)
                if isinstance(v.c, list):
                    out.extend(v.c[:1000])
                else:
                    out.append(Val(NOVAL, _tags(v)))
            else:
                out.append(self.ev(a, scope))
        return out

    def invoke(self, f: Func | None, args: list, this=None, leftover=False) -> Val:
        if f is None:
            return UNKNOWN
        node = f.node
        nid = id(node)
        if not leftover:
            if f in self.stack or len(self.stack) >= self.call_depth_limit or f.calls > 24:
                return Val(NOVAL, _tags(*args))
        f.calls += 1
        self.reached.add(nid)
        sc = Scope(f.scope)
        sc.vars["arguments"] = Val(list(args))
        if this is not None:
            sc.vars["this"] = this
        for i, p in enumerate(node[3]):
            if p[0] == "prest":
                self.bind(p[1], Val(list(args[i:])), sc, declare=True)
                break
            self.bind(p, args[i] if i < len(args) else Val(UNDEF), sc, declare=True)
        if node[2] and node[4] is not None and node[2] not in sc.vars:
            sc.vars.setdefault(node[2], _func_val(f))
        self.stack.append(f)
        self.returns.append([])
        saved_scope, self.cur_scope = self.cur_scope, sc
        try:
            if node[5] is not None:
                rv = [self.ev(node[5], sc)]
            else:
                self.hoist(node[4], sc)
                self.exec_list(node[4], sc)
                rv = self.returns[-1]
        finally:
            self.stack.pop()
            self.returns.pop()
            self.cur_scope = saved_scope
        if not rv:
            return Val(UNDEF)
        if len(rv) == 1:
            return rv[0]
        out = rv[0]
        for v in rv[1:5]:
            out = self.alts(out, v)
        return out

    def callback(self, v: Val, args: list):
        """Run a function handed to a call (event handler, .then, timer) at the current phase."""
        f = _meta(v, "fn")
        if f is not None:
            return self.invoke(f, args)
        return None

    def run_callbacks(self, args: list, cb_args: list):
        for a in args:
            if _meta(a, "fn") is not None:
                self.callback(a, cb_args)
            elif isinstance(a.c, dict):
                for x in list(a.c.values())[:20]:
                    if _meta(x, "fn") is not None:
                        self.callback(x, cb_args)

    def apply(self, fnv: Val, args: list, recv, n, new=False) -> Val:
        pos = n[1]
        f = _meta(fnv, "fn")
        if f is not None:
            return self.invoke(f, args, recv if isinstance(recv, Val) and isinstance(recv.c, dict) else None)
        bound = _meta(fnv, "bound")
        if bound is None and fnv.ref and "." in fnv.ref and fnv.ref.rsplit(".", 1)[1] in ("call", "apply", "bind"):
            head, how = fnv.ref.rsplit(".", 1)
            bound = (Val(NOVAL, (), ALIASES.get(head, head), fnv.meta), how)
        if bound is not None:
            target, how = bound
            if how == "call":
                return self.apply(target, args[1:], None, n)
            if how == "apply":
                rest = args[1].c if len(args) > 1 and isinstance(args[1].c, list) else []
                return self.apply(target, list(rest), None, n)
            return target
        if fnv.ref:
            r = self.call_ref(fnv, args, n, new)
            if r is not None:
                return r
        if recv is not None:
            r = self.call_method(recv, n, args, fnv)
            if r is not None:
                return r
        # unknown function: its callbacks run now, its result carries what went in (but a method of an opaque object
        # is not itself made from a blob)
        tags = (_tags(recv) - {OPAQUE} | _tags(*args)) if recv is not None else _tags(*args)
        tags = tags - {CRED_PATH, AUTOSTART_PATH}
        if args and all(a.known and isinstance(a.c, (str, int, float, bytes, list)) for a in args) and \
                any(isinstance(a.c, (str, bytes)) and len(a.c) >= 24 or isinstance(a.c, list) and len(a.c) >= 16
                    for a in args) and (recv is None or recv.known):
            tags = tags | {OPAQUE}                     # a blob in, unknown out: a decoder that could not be followed
        callee = n[2] if len(n) > 2 else None
        name = callee[3][2] if recv is not None and isinstance(callee, tuple) and callee[0] == "member" \
            and isinstance(callee[3], tuple) and callee[3][0] == "str" else None
        if name in ("map", "flatMap") and args and _meta(args[0], "fn") is not None:
            # an unknown array mapped through a function: the items are what the function made of them
            r = self.callback(args[0], [Val(NOVAL, tags), Val(NOVAL)])
            return Val(NOVAL, _tags(r) if isinstance(r, Val) else frozenset())
        self.run_callbacks(args, [Val(NOVAL, tags)] * 2)
        return Val(NOVAL, tags)

    # ---------------------------------------------------------------- built-ins by name
    def call_ref(self, fnv: Val, args: list, n, new) -> Val | None:
        ref = fnv.ref
        pos = n[1]
        hidden = bool(_meta(fnv, "hidden"))
        a0 = args[0] if args else Val(UNDEF)
        a1 = args[1] if len(args) > 1 else Val(UNDEF)
        head, _, meth = ref.rpartition(".")
        if hidden and (ref in EXEC_REFS or (head == "child_process" and meth in PROC_METHODS)):
            self.emit("hidden_call", pos)
        if ref in ("require", "import"):
            r = self.require(a0, pos)
            # a module name that is not written as a plain string literal counts as a hidden name
            literal = len(n) > 3 and isinstance(n[3], list) and n[3] and n[3][0][0] == "str" and not n[3][0][3]
            return _with_meta(r, hidden=True) if (hidden or not literal) and r.ref else r
        if ref == "eval":
            return self.exec_code(a0, pos, scope_eval=not _meta(fnv, "indirect"))
        if ref in ("Function", "Function.prototype.constructor") or ref.endswith(".constructor.constructor"):
            body = args[-1] if args else Val("")
            self.exec_code(body, pos, scope_eval=False)
            return Val(NOVAL, (), None, {"fn": None})
        if head == "vm" and meth in ("runInNewContext", "runInThisContext", "runInContext", "Script", "compileFunction",
                                     "SourceTextModule"):
            self.exec_code(a0, pos, scope_eval=False)
            return Val(NOVAL, (), None, {"obj": "vmscript"})
        if head == "child_process" and meth in PROC_METHODS:
            return self.run_process(meth, args, pos)
        if ref in ("setTimeout", "setInterval", "setImmediate", "queueMicrotask", "process.nextTick", "Promise",
                   "process.on", "process.once", "process.addListener"):
            if ref == "Promise":
                noop = Val(NOVAL, (), None, {"fn": None})
                self.run_callbacks(args, [noop, noop])
                return Val(NOVAL)
            self.run_callbacks(args, [Val(NOVAL)] * 2)
            return Val(NOVAL)
        if ref == "Reflect.apply":
            rest = args[2].c if len(args) > 2 and isinstance(args[2].c, list) else []
            return self.apply(a0, list(rest), None, n)
        if ref == "Reflect.construct":
            rest = a1.c if isinstance(a1.c, list) else []
            return self.apply(a0, list(rest), None, n, new=True)
        r = self.call_source(ref, head, meth, args, pos)
        if r is not None:
            return r
        r = self.call_decoder(ref, head, meth, args)
        if r is not None:
            return r
        r = self.call_fs(ref, head, meth, args, pos)
        if r is not None:
            return r
        r = self.call_net(ref, head, meth, args, pos, n)
        if r is not None:
            return r
        return None

    def require(self, a0: Val, pos) -> Val:
        name = a0.s() if a0.known else None
        if name is None:
            return Val(NOVAL, _tags(a0))
        if name.startswith((".", "/")):
            return Val(NOVAL, frozenset({LOCAL}), None, {"local": name})
        return Val(NOVAL, (), _mod(name))

    # ---------------------------------------------------------------- code execution
    def exec_code(self, v: Val, pos, scope_eval=True) -> Val:
        """eval / Function / vm: a recovered string is analyzed as code at this phase; an unrecovered one is judged by
        where its data came from."""
        recovered = False
        result = Val(NOVAL)
        for alt in (_meta(v, "alts") or [v]):
            s = alt.s() if alt.known else None
            if s is None:
                continue
            recovered = True
            if self.depth + 1 > int(self.ctx.limits["max_depth"]):
                continue
            sub = Analyzer(self.ctx, s, self.file, self.phase, self.depth + 1, self.line(pos),
                           Scope(self.cur_scope if scope_eval else self.globals))
            sub.steps, sub.iters = self.steps, self.iters
            try:
                stmts = parse(s, self.ctx.check_time)
                sub.funcs = []
                sub.hoist(stmts, sub.globals)
                if scope_eval and len(stmts) == 1 and stmts[0][0] == "expr":
                    result = sub.ev(stmts[0][2], sub.globals)
                else:
                    sub.exec_list(stmts, sub.globals)
                sub.phase_leftovers()
            except LimitExceeded:
                raise
            except Exception:                          # noqa: BLE001
                pass
            self.steps, self.iters = sub.steps, sub.iters
        if not recovered:
            if not isinstance(v.c, str) and v.known and not isinstance(v.c, (bytes, bytearray)):
                return result                          # eval(42), eval(undefined)
            self.tag_exec(v, pos)
        return result

    def phase_leftovers(self):
        saved = self.phase
        self.phase = "call"
        k = 0
        while k < len(self.funcs):
            f = self.funcs[k]
            k += 1
            if id(f.node) not in self.reached:
                self.invoke(f, [], None, leftover=True)
        self.phase = saved

    def tag_exec(self, v: Val, pos):
        tags = _tags(v)
        if NET in tags:
            self.emit("download_exec", pos)
        if DECODED in tags:
            self.emit("decode_exec", pos)
        # unknown because it is data (a parameter, a table entry) is not unreadable; computed from constants by code
        # that could not be followed, or taken from the environment, is
        if not tags & {NET, DECODED, LOCAL} and tags & {OPAQUE, ENV} and self.auto:
            self.emit("unreadable_exec", pos)

    # ---------------------------------------------------------------- processes
    def run_process(self, meth: str, args: list, pos) -> Val:
        a0 = args[0] if args else Val(UNDEF)
        argv: list[Val] = []
        opts = None
        if meth in ("exec", "execSync"):
            cmd_vals = [a0]
            opts = args[1] if len(args) > 1 and isinstance(args[1].c, dict) else None
        else:
            prog = a0
            rest = args[1] if len(args) > 1 else None
            if rest is not None and isinstance(rest.c, list):
                argv = list(rest.c)
                opts = args[2] if len(args) > 2 and isinstance(args[2].c, dict) else None
            elif rest is not None and isinstance(rest.c, dict):
                opts = rest
            elif rest is not None and not rest.known and _meta(rest, "fn") is None:
                argv = [rest]
            if meth == "fork":
                prog, argv = Val("node"), [a0] + argv
            cmd_vals = [prog] + argv
        tags = _tags(*cmd_vals)
        prog_v = cmd_vals[0]
        variants = _meta(prog_v, "alts") or [prog_v]
        info = {"programs": [], "sysinfo": False, "network": False}
        any_known = False
        for pv in variants[:4]:
            if not pv.known or not isinstance(pv.c, str):
                continue
            any_known = True
            if meth in ("exec", "execSync"):
                text = pv.c
            else:
                text = " ".join(_quote(x) for x in [pv] + argv)
            r = self.ctx.shell(text, self.phase, self.file, self.line(pos), self.depth)
            info["programs"] += r.get("programs", [])
            info["sysinfo"] |= bool(r.get("sysinfo"))
            info["network"] |= bool(r.get("network"))
        if not any_known:
            hint = _meta(prog_v, "partial")
            if hint and meth in ("exec", "execSync"):
                r = self.ctx.shell(hint.replace(PH, "?"), self.phase, self.file, self.line(pos), self.depth)
                info["programs"] += r.get("programs", [])
                info["sysinfo"] |= bool(r.get("sysinfo"))
                any_known = bool(r.get("programs")) and r["programs"][0] not in ("?", "")
            if not any_known:
                # a program run with an argument list (a platform binary at a computed path) is not code text:
                # judged by where it came from (downloaded, decoded), not as unreadable
                if meth not in ("exec", "execSync"):
                    tags = tags - {OPAQUE, ENV}
                self.tag_exec(Val(NOVAL, tags), pos)
        else:
            unknown_tags = _tags(*[x for x in cmd_vals if not x.known])
            progs = [p for p in info["programs"] if p]
            if unknown_tags & {NET, DECODED} and progs and (progs[0] in self.pol.interpreters
                                                            or progs[0].startswith(("python", "node", "perl", "ruby"))):
                self.tag_exec(Val(NOVAL, unknown_tags & {NET, DECODED}), pos)
        for p in info["programs"]:
            if p and p not in ("?",) and p not in self.pol.build and not p.startswith("python"):
                self.emit("install_process", pos)
                break
        # a shell whose input / output is a socket
        shell_child = any(p in SHELL_PROGS or p.rsplit("/", 1)[-1] in SHELL_PROGS for p in info["programs"][:1])
        if shell_child and opts is not None and SOCK in _tags(opts):
            self.emit("remote_shell", pos)
        out_tags = set()
        if info["sysinfo"]:
            out_tags.add(SYSINFO)
        if info["network"]:
            out_tags.add(NET)
        out = Val(NOVAL, frozenset(out_tags), None, {"obj": "child", "shell": shell_child})
        cbs = [a for a in args if _meta(a, "fn") is not None]
        for cb in cbs:
            self.callback(cb, [Val(NOVAL), Val(NOVAL, frozenset(out_tags)), Val(NOVAL)])
        if meth in ("execSync", "execFileSync", "spawnSync"):
            return Val(NOVAL, frozenset(out_tags))
        return out

    # ---------------------------------------------------------------- sources
    def call_source(self, ref, head, meth, args, pos) -> Val | None:
        if head == "os":
            if meth == "homedir":
                return Val("~", frozenset({SYSINFO}))
            if meth in ("hostname", "userInfo", "networkInterfaces", "cpus"):
                return Val(NOVAL, frozenset({SYSINFO}))
            if meth == "tmpdir":
                return Val("/tmp")
            if meth in ("platform", "type", "arch", "release", "endianness", "EOL", "totalmem", "freemem", "uptime"):
                return Val(NOVAL)
        if ref in ("process.cwd",):
            return Val(NOVAL, frozenset({SYSINFO}))
        if ref in ("JSON.stringify", "String", "Object.keys", "Object.values", "Object.entries", "Object.assign",
                   "Array.from", "Object.fromEntries"):
            a0 = args[0] if args else Val(UNDEF)
            if ref == "JSON.stringify":
                # a JSON-quoted value is a literal: fetched / decoded data pasted into code this way stays data
                # (d3's new Function("d", "return {" + JSON.stringify(column) ...)); secrets keep their tags
                py = _to_py(a0)
                if py is not NOVAL:
                    try:
                        return self.mk(json.dumps(py, separators=(",", ":"), ensure_ascii=False),
                                       _tags(a0) - {NET, DECODED})
                    except (TypeError, ValueError):
                        pass
                return Val(NOVAL, _tags(*args) - {NET, DECODED})
            if ref == "String":
                s = _to_str(a0.c) if a0.known else None
                return self.mk(s, a0.tags) if s is not None else Val(NOVAL, _tags(a0))
            if ref in ("Object.keys", "Object.values", "Object.entries") and isinstance(a0.c, dict):
                items = list(a0.c.items())[:self.max_iter]
                if ref == "Object.keys":
                    return Val([Val(k) for k, _ in items], a0.tags)
                if ref == "Object.values":
                    return Val([v for _, v in items], a0.tags)
                return Val([Val([Val(k), v]) for k, v in items], a0.tags)
            if ref == "Array.from" and isinstance(a0.c, (list, str)):
                items = list(a0.c) if isinstance(a0.c, list) else [Val(ch, a0.tags) for ch in a0.c[:10000]]
                if len(args) > 1 and _meta(args[1], "fn") is not None:
                    return self.map_items(items, args[1], a0.tags)
                return Val(items, a0.tags)
            if ref == "Object.assign" and args and isinstance(a0.c, dict):
                for src in args[1:]:
                    if isinstance(src.c, dict):
                        a0.c.update(src.c)
                    else:
                        return Val(NOVAL, _tags(*args))
                return a0
            return Val(NOVAL, _tags(*args))
        if ref in ("console.log", "console.error", "console.warn", "console.info", "console.debug"):
            return Val(UNDEF)
        return None

    def map_items(self, items, fn, tags=frozenset()) -> Val:
        out = []
        if self.iters + len(items) > self.max_iter:
            return Val(NOVAL, _tags(*items[:50]) | tags)
        self.iters += len(items)
        for i, it in enumerate(items):
            out.append(self.apply(fn, [it, Val(i)], None, ("call", 0)))
        return Val(out, tags)

    # ---------------------------------------------------------------- decoders
    def call_decoder(self, ref, head, meth, args) -> Val | None:
        a0 = args[0] if args else Val(UNDEF)
        a1 = args[1] if len(args) > 1 else Val(UNDEF)
        # decoding a constant / the package's own data is hiding; decoding data that flows in is serialization
        const = a0.known or len((_meta(a0, "partial") or "").replace(PH, "")) >= 24 or \
            bool(a0.tags & {OPAQUE, LOCAL, DECODED})
        dec = frozenset({DECODED}) if const else frozenset()
        if ref in ("atob",):
            s = a0.s() if a0.known else None
            if s is not None:
                try:
                    return self.mk(base64.b64decode(s + "===").decode("latin-1"), a0.tags | dec)
                except (ValueError, TypeError):
                    pass
            return Val(NOVAL, _tags(a0) | dec)
        if ref == "btoa":
            s = a0.s() if a0.known else None
            if s is not None:
                try:
                    return self.mk(base64.b64encode(s.encode("latin-1")).decode(), a0.tags)
                except (ValueError, UnicodeEncodeError):
                    pass
            return Val(NOVAL, _tags(a0))
        if ref in ("decodeURIComponent", "decodeURI", "unescape"):
            s = a0.s() if a0.known else None
            if s is not None:
                if ref == "unescape":
                    s = re.sub(r"%u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
                    return self.mk(urllib.parse.unquote(s, "latin-1"), a0.tags | dec)
                return self.mk(urllib.parse.unquote(s), a0.tags | dec)
            return Val(NOVAL, _tags(a0) | dec)
        if ref in ("encodeURIComponent", "encodeURI", "escape"):
            s = a0.s() if a0.known else None
            return self.mk(urllib.parse.quote(s, safe=""), a0.tags) if s is not None else Val(NOVAL, _tags(a0))
        if ref in ("String.fromCharCode", "String.fromCodePoint"):
            chars = []
            for a in args:
                if isinstance(a.c, list):
                    vals = a.c
                else:
                    vals = [a]
                for x in vals:
                    num = _to_num(x.c) if x.known else None
                    if num is None:
                        return Val(NOVAL, _tags(*args) | dec)
                    try:
                        chars.append(chr(int(num) & (0xFFFF if ref.endswith("Code") else 0x10FFFF)))
                    except (ValueError, OverflowError):
                        return Val(NOVAL, _tags(*args) | dec)
            return self.mk("".join(chars), _tags(*args) | dec)
        if ref in ("parseInt", "Number.parseInt", "Number", "parseFloat", "Number.parseFloat"):
            s = _to_str(a0.c) if a0.known else None
            if s is None:
                return Val(NOVAL, _tags(a0))
            try:
                if ref.endswith("parseInt"):
                    radix = int(_to_num(a1.c) or 10) if a1.known and a1.c is not UNDEF else 10
                    m = re.match(r"\s*([+-]?)(0[xX])?([0-9a-zA-Z]+)", s)
                    if not m:
                        return Val(float("nan"))
                    if m.group(2) and radix in (10, 16) and not (a1.known and a1.c is not UNDEF and radix == 10):
                        radix = 16
                    digits = ""
                    for ch in m.group(3):
                        if int(ch, 36) >= radix:
                            break
                        digits += ch
                    return Val(int(m.group(1) + digits, radix) if digits else float("nan"), a0.tags)
                return Val(float(s) if "." in s or "e" in s.lower() else int(s.strip() or 0), a0.tags)
            except (ValueError, TypeError):
                return Val(float("nan"))
        if ref in ("Buffer.from", "Buffer", "Buffer.alloc", "Uint8Array", "Uint8Array.from", "TextEncoder"):
            enc = (a1.s() or "utf8").lower().replace("-", "") if a1.known and isinstance(a1.c, str) else "utf8"
            if isinstance(a0.c, list):
                try:
                    data = bytes(int(_to_num(x.c)) & 0xFF for x in a0.c)
                    return self.mk(data, _tags(a0) | dec, buf=True)
                except (TypeError, ValueError):
                    return Val(NOVAL, _tags(a0) | dec)
            if isinstance(a0.c, (bytes, bytearray)):
                return self.mk(bytes(a0.c), a0.tags, buf=True)
            s = a0.s() if a0.known else None
            decoding = enc in ("base64", "base64url", "hex")
            if s is None:
                return Val(NOVAL, _tags(a0) | (dec if decoding else frozenset()), None, {"buf": True})
            try:
                if enc in ("base64", "base64url"):
                    t = s.replace("-", "+").replace("_", "/")
                    data = base64.b64decode(re.sub(r"[^A-Za-z0-9+/]", "", t) + "===")
                elif enc == "hex":
                    h = re.sub(r"[^0-9a-fA-F]", "", s)
                    data = bytes.fromhex(h[:len(h) // 2 * 2])
                elif enc in ("latin1", "binary", "ascii"):
                    data = s.encode("latin-1", "replace")
                elif enc in ("utf16le", "ucs2"):
                    data = s.encode("utf-16-le")
                else:
                    data = s.encode("utf-8", "surrogatepass")
            except (ValueError, TypeError):
                return Val(NOVAL, a0.tags | dec)
            return self.mk(data, a0.tags | (dec if decoding else frozenset()), buf=True)
        if ref == "Buffer.concat":
            if isinstance(a0.c, list) and all(isinstance(x.c, (bytes, bytearray)) for x in a0.c):
                return self.mk(b"".join(bytes(x.c) for x in a0.c), _tags(a0), buf=True)
            return Val(NOVAL, _tags(a0), None, {"buf": True})
        if head == "zlib" and meth in ("inflateSync", "inflateRawSync", "gunzipSync", "unzipSync",
                                       "brotliDecompressSync", "inflate", "gunzip", "unzip", "inflateRaw"):
            data = a0.c if isinstance(a0.c, (bytes, bytearray)) else None
            if data is not None and not meth.startswith("brotli"):
                wbits = {"inflateRawSync": -15, "inflateRaw": -15}.get(meth, 47)
                try:
                    d = zlib.decompressobj(wbits)
                    out = d.decompress(bytes(data), self.max_string)
                    if not d.unconsumed_tail:
                        return self.mk(out, a0.tags | dec, buf=True)
                except zlib.error:
                    pass
            r = Val(NOVAL, _tags(a0) | dec, None, {"buf": True})
            self.run_callbacks(args[1:], [Val(NOVAL), r])
            return r
        if head == "crypto" and meth in ("createDecipheriv", "createDecipher", "privateDecrypt", "publicDecrypt"):
            return Val(NOVAL, _tags(*args) | dec, None, {"obj": "decipher"})
        if ref == "TextDecoder":
            return Val(NOVAL, (), None, {"obj": "textdecoder"})
        if ref == "JSON.parse":
            s = a0.s() if a0.known else None
            if s is not None:
                try:
                    return _from_py(json.loads(s), a0.tags)
                except (ValueError, RecursionError):
                    pass
            return Val(NOVAL, _tags(a0))
        return None

    # ---------------------------------------------------------------- files
    def file_tags(self, p: Val) -> frozenset:
        hint = p.s() if p.known else _meta(p, "partial")
        cls = path_class(hint.replace(PH, "x")) if isinstance(hint, str) else None
        if CRED_PATH in p.tags or cls == "credential":
            return frozenset({SECRET})
        if p.known and isinstance(hint, str) and self.ctx.was_downloaded(hint):
            return frozenset({NET})
        if cls == "local" and p.known:
            return frozenset({LOCAL})
        return frozenset()

    def write_file(self, p: Val, data: Val | None, pos):
        hint = p.s() if p.known else _meta(p, "partial")
        cls = path_class(hint.replace(PH, "x")) if isinstance(hint, str) else None
        if cls == "autostart" or AUTOSTART_PATH in p.tags:
            self.emit("persistence", pos)
        if data is not None and NET in _tags(data) and p.known and isinstance(hint, str):
            self.ctx.add_downloaded(hint)

    def call_fs(self, ref, head, meth, args, pos) -> Val | None:
        if head not in ("fs", "fs.promises", "fs-extra", "graceful-fs") and ref != "fs":
            if head == "path":
                return self.call_path(meth, args)
            return None
        a0 = args[0] if args else Val(UNDEF)
        a1 = args[1] if len(args) > 1 else Val(UNDEF)
        if meth in ("readFileSync", "readFile", "readJson", "readJsonSync", "createReadStream", "readlinkSync"):
            tags = self.file_tags(a0)
            r = Val(NOVAL, tags, None, {"obj": "stream", "src": tags} if meth == "createReadStream" else None)
            self.run_callbacks(args[1:], [Val(NOVAL), Val(NOVAL, tags)])
            if head == "fs.promises" or meth == "readFile" and not any(_meta(a, "fn") for a in args[1:]):
                return Val(NOVAL, tags, None, {"promise": Val(NOVAL, tags)})
            return r
        if meth in ("readdirSync", "readdir", "globSync", "statSync", "existsSync", "lstatSync"):
            hint = a0.s() if a0.known else _meta(a0, "partial")
            cls = path_class(hint.replace(PH, "x")) if isinstance(hint, str) else None
            extra = frozenset({CRED_PATH}) if cls == "credential" or CRED_PATH in a0.tags else frozenset()
            if meth in ("existsSync", "statSync", "lstatSync"):
                return Val(NOVAL)
            r = Val(NOVAL, extra)
            self.run_callbacks(args[1:], [Val(NOVAL), r])
            return r
        if meth in ("writeFileSync", "writeFile", "appendFileSync", "appendFile", "outputFileSync", "outputFile",
                    "writeJsonSync", "writeJson"):
            self.write_file(a0, a1, pos)
            self.run_callbacks(args[2:], [Val(NOVAL)])
            return Val(UNDEF)
        if meth == "createWriteStream":
            self.write_file(a0, None, pos)
            return Val(NOVAL, (), None, {"obj": "wstream", "path": a0})
        if meth in ("copyFileSync", "copyFile", "renameSync", "rename", "cpSync", "symlinkSync", "linkSync"):
            src_tags = self.file_tags(a0)
            self.write_file(a1, Val(NOVAL, src_tags) if NET in src_tags else None, pos)
            return Val(UNDEF)
        if meth in ("chmodSync", "chmod"):
            if a0.known and isinstance(a0.c, str):
                self.ctx.mark_executable(a0.c)
            return Val(UNDEF)
        return Val(NOVAL)

    def call_path(self, meth, args) -> Val | None:
        if meth in ("join", "resolve", "normalize", "posix.join", "win32.join"):
            parts = []
            for i, a in enumerate(args):
                if i:
                    parts.append(Val("/"))
                parts.append(a)
            v = self.concat(parts)
            if v.known and isinstance(v.c, str):
                s = re.sub(r"/+", "/", v.c)
                s = re.sub(r"(^|/)\./", r"\1", s)
                return Val(s, v.tags)
            return v
        a0 = args[0] if args else Val(UNDEF)
        if not a0.known or not isinstance(a0.c, str):
            return Val(NOVAL, _tags(a0))
        s = a0.c.replace("\\", "/")
        if meth == "dirname":
            return Val(s.rsplit("/", 1)[0] if "/" in s else ".", a0.tags)
        if meth == "basename":
            b = s.rstrip("/").rsplit("/", 1)[-1]
            if len(args) > 1 and isinstance(args[1].c, str) and b.endswith(args[1].c):
                b = b[:-len(args[1].c)]
            return Val(b, a0.tags)
        if meth == "extname":
            b = s.rsplit("/", 1)[-1]
            return Val("." + b.rsplit(".", 1)[1] if "." in b[1:] else "", a0.tags)
        return Val(NOVAL, a0.tags)

    # ---------------------------------------------------------------- network
    def send(self, target: Val | None, payload: list, pos):
        """Data leaving the machine: judged by where the data came from and the kind of address."""
        tags = _tags(*payload) | (_tags(target) if target is not None else frozenset())
        cls = None
        if target is not None:
            for t in (_meta(target, "alts") or [target]):
                hint = t.s() if t.known else _meta(t, "partial")
                if isinstance(hint, str):
                    cls = endpoint_class(hint.replace(PH, "x"))
                    if cls:
                        break
        if SECRET in tags or (SECRET_ENV in tags and cls):
            self.emit("secret_exfil", pos)
        if SYSINFO in tags:
            self.emit("suspicious_send" if cls else "sysinfo_beacon", pos)
        elif cls in ("collector", "messenger") and self.auto:
            self.emit("suspicious_send", pos)

    def url_of(self, v: Val) -> Val:
        """The address of a request: a URL string, or an options object {protocol, hostname/host, port, path}."""
        if isinstance(v.c, dict):
            d = v.c
            if "url" in d or "uri" in d:
                return d.get("url") or d.get("uri")
            parts = [d.get("protocol") or Val("https:"), Val("//"), d.get("hostname") or d.get("host") or Val(PH)]
            if "port" in d:
                parts += [Val(":"), d["port"]]
            if "path" in d:
                parts.append(d["path"])
            return self.concat(parts)
        return v

    def call_net(self, ref, head, meth, args, pos, n) -> Val | None:
        a0 = args[0] if args else Val(UNDEF)
        a1 = args[1] if len(args) > 1 else Val(UNDEF)
        net_res = Val(NOVAL, frozenset({NET}), None, {"obj": "res"})
        if head in HTTP_MODS and meth in ("get", "request"):
            url = self.url_of(a0)
            opts = a1 if isinstance(a1.c, dict) else None
            payload = [a0] + ([opts] if opts is not None else [])
            if meth == "get":
                self.send(url, payload, pos)
            self.run_callbacks(args[1:], [net_res])
            return Val(NOVAL, frozenset({NET}), None, {"obj": "req", "url": url, "pay": payload, "sent": meth == "get"})
        mod = ref.split(".")[0]
        if ref in ("fetch", "undici.fetch") or mod in CLIENT_MODS and (ref == mod or meth in SEND_METHODS or ref == f"{mod}.default"):
            url = self.url_of(a0)
            payload = list(args)
            self.send(url, payload, pos)
            self.run_callbacks(args, [Val(NOVAL), net_res, Val(NOVAL, frozenset({NET}))])
            pr = Val(NOVAL, frozenset({NET}), None, {"obj": "promise", "promise": net_res})
            return pr
        if head in ("dns", "dns.promises") and (meth.startswith("resolve") or meth in ("lookup", "reverse")):
            self.send(a0, [a0], pos)
            self.run_callbacks(args[1:], [Val(NOVAL), Val(NOVAL, frozenset({NET}))])
            return Val(NOVAL, frozenset({NET}))
        if head in ("net", "tls") and meth in ("connect", "createConnection", "Socket"):
            host = a1 if a0.known and isinstance(a0.c, (int, float)) else (a0 if isinstance(a0.c, str) else None)
            if isinstance(a0.c, dict):
                host = a0.c.get("host") or a0.c.get("hostname")
            sock = Val(NOVAL, frozenset({SOCK}), None, {"obj": "sock", "host": [host]})
            self.run_callbacks(args, [])
            return sock
        if head == "dgram" and meth == "createSocket":
            return Val(NOVAL, frozenset({SOCK}), None, {"obj": "dgram", "host": [None]})
        if ref in ("WebSocket", "ws", "ws.WebSocket"):
            return Val(NOVAL, frozenset({NET}), None, {"obj": "req", "url": a0, "pay": [a0], "sent": False})
        if ref == "XMLHttpRequest":
            return Val(NOVAL, frozenset({NET}), None, {"obj": "xhr", "url": [None]})
        return None

    # ---------------------------------------------------------------- methods of values and objects
    def call_method(self, recv: Val, n, args, fnv) -> Val | None:
        callee = n[2]
        if callee[0] != "member":
            return None
        name = callee[3][2] if not callee[4] or callee[3][0] == "str" else _meta(fnv, "name")
        if name is None:
            return None
        c = recv.c
        kind = _meta(recv, "obj")
        pos = n[1]
        a0 = args[0] if args else Val(UNDEF)
        if name in ("on", "once", "addListener", "addEventListener", "then", "catch", "finally", "pipe", "write",
                    "end", "send", "connect", "update", "final", "decode", "open", "setRequestHeader"):
            r = self.object_method(recv, kind, name, args, pos)
            if r is not None:
                return r
        if isinstance(c, str):
            return self.str_method(recv, name, args)
        if isinstance(c, list):
            return self.list_method(recv, name, args)
        if isinstance(c, (bytes, bytearray)):
            return self.bytes_method(recv, name, args)
        if isinstance(c, (int, float)) and not isinstance(c, bool) and name == "toString":
            radix = int(_to_num(a0.c) or 10) if a0.known and a0.c is not UNDEF else 10
            return Val(_radix(c, radix), recv.tags)
        if _meta(recv, "buf") and name == "toString":
            return Val(NOVAL, recv.tags)
        return None

    def object_method(self, recv, kind, name, args, pos) -> Val | None:
        a0 = args[0] if args else Val(UNDEF)
        tags = recv.tags - {CRED_PATH, AUTOSTART_PATH}
        if name in ("on", "once", "addListener", "addEventListener"):
            ev_name = a0.s() if a0.known else None
            data = Val(NOVAL, tags | ({NET} if kind in ("res", "req", "sock") and ev_name in ("data", "message", "response")
                                      else frozenset()))
            if kind == "req" and ev_name == "response":
                data = Val(NOVAL, frozenset({NET}), None, {"obj": "res"})
            self.run_callbacks(args[1:], [data, data])
            return recv
        if name in ("then", "catch", "finally"):
            inner = _meta(recv, "promise") or Val(NOVAL, tags)
            if name == "then":
                f = args[0] if args else None
                r = self.callback(f, [inner]) if f is not None else None
                for extra in args[1:]:
                    self.callback(extra, [Val(NOVAL)])
                res = r if r is not None else Val(NOVAL, tags)
                return Val(NOVAL, _tags(res) | tags, None, {"obj": "promise", "promise": res})
            self.run_callbacks(args, [Val(NOVAL)])
            return recv
        if name == "pipe":
            dest = a0
            dkind = _meta(dest, "obj")
            if dkind == "wstream" and NET in recv.tags:
                p = _meta(dest, "path")
                if p is not None and p.known and isinstance(p.c, str):
                    self.ctx.add_downloaded(p.c)
            child_src = kind == "childio" and _meta(_meta(recv, "child") or Val(NOVAL), "shell")
            child_dst = dkind == "childio" and _meta(_meta(dest, "child") or Val(NOVAL), "shell")
            if (child_src and SOCK in dest.tags) or (child_dst and SOCK in recv.tags):
                self.emit("remote_shell", pos)
            if dkind == "childio" and NET in recv.tags and _meta(_meta(dest, "child") or Val(NOVAL), "shell"):
                self.emit("download_exec", pos)
            return dest
        if kind == "req" and name in ("write", "end", "send"):
            pay = [x for x in args if _meta(x, "fn") is None]
            self.send(_meta(recv, "url"), pay + list(_meta(recv, "pay") or []), pos)
            self.run_callbacks(args, [Val(NOVAL)])
            return recv
        if kind == "xhr" and name == "open":
            box = _meta(recv, "url")
            if box is not None and len(args) > 1:
                box[0] = args[1]
            return Val(UNDEF)
        if kind == "xhr" and name == "send":
            box = _meta(recv, "url") or [None]
            self.send(box[0], args + ([box[0]] if box[0] is not None else []), pos)
            return Val(UNDEF)
        if kind in ("sock", "dgram") and name in ("connect", "write", "end", "send"):
            box = _meta(recv, "host") or [None]
            if name == "connect":
                a1 = args[1] if len(args) > 1 else Val(UNDEF)
                box[0] = a1 if a0.known and isinstance(a0.c, (int, float)) else (
                    (a0.c.get("host") if isinstance(a0.c, dict) else a0))
                self.run_callbacks(args, [])
                return recv
            pay = [x for x in args if _meta(x, "fn") is None]
            target = box[0]
            if kind == "dgram" and len(args) >= 3:
                target = args[2]
            self.send(target, pay, pos)
            return recv
        if kind == "decipher" and name in ("update", "final"):
            return Val(NOVAL, _tags(recv, *args) | {DECODED})
        if kind == "textdecoder" and name == "decode":
            if isinstance(a0.c, (bytes, bytearray)):
                return self.mk(bytes(a0.c).decode("utf-8", "replace"), a0.tags)
            return Val(NOVAL, _tags(a0))
        return None

    def str_method(self, recv: Val, name, args) -> Val | None:
        s = recv.c
        tags = recv.tags
        a = [x.c if x.known else NOVAL for x in args]
        a0 = a[0] if a else UNDEF
        a1 = a[1] if len(a) > 1 else UNDEF
        try:
            if name in ("toString", "valueOf", "toLocaleString", "normalize"):
                return recv
            if name in ("toLowerCase", "toLocaleLowerCase"):
                return Val(s.lower(), tags)
            if name in ("toUpperCase", "toLocaleUpperCase"):
                return Val(s.upper(), tags)
            if name in ("trim", "trimStart", "trimEnd", "trimLeft", "trimRight"):
                f = {"trim": s.strip, "trimStart": s.lstrip, "trimLeft": s.lstrip}.get(name, s.rstrip)
                return Val(f(), tags)
            if name == "split":
                if a0 is UNDEF:
                    return Val([recv], tags)
                if isinstance(a0, str):
                    parts = list(s) if a0 == "" else s.split(a0)
                    if len(parts) > self.max_iter:
                        return Val(NOVAL, tags)
                    return Val([Val(p, tags) for p in parts], tags)
                rx = _meta(args[0], "regex")
                if rx:
                    parts = _py_regex(rx[0]).split(s)
                    return Val([Val(p, tags) for p in parts if p is not None][:self.max_iter], tags)
                return Val(NOVAL, tags)
            if name in ("slice", "substring", "substr"):
                n = len(s)
                st = int(_to_num(a0) or 0) if a0 is not UNDEF else 0
                if name == "substr":
                    ln = int(_to_num(a1)) if a1 is not UNDEF and a1 is not NOVAL else n
                    st = st + n if st < 0 else st
                    return Val(s[max(st, 0):max(st, 0) + max(ln, 0)], tags)
                en = int(_to_num(a1)) if a1 is not UNDEF and a1 is not NOVAL else n
                if name == "substring":
                    st, en = max(0, min(st, n)), max(0, min(en, n))
                    st, en = min(st, en), max(st, en)
                return Val(s[st:en], tags)
            if name in ("charAt", "at"):
                i = int(_to_num(a0) or 0)
                if name == "charAt" and i < 0:
                    return Val("", tags)
                try:
                    return Val(s[i], tags)
                except IndexError:
                    return Val("" if name == "charAt" else UNDEF, tags)
            if name in ("charCodeAt", "codePointAt"):
                i = int(_to_num(a0) or 0) if a0 is not UNDEF else 0
                return Val(ord(s[i]) if 0 <= i < len(s) else float("nan"), tags)
            if name == "concat":
                return self.concat([recv] + list(args))
            if name in ("indexOf", "lastIndexOf", "includes", "startsWith", "endsWith", "search"):
                if not isinstance(a0, str):
                    return Val(NOVAL)
                return Val({"indexOf": s.find, "lastIndexOf": s.rfind}[name](a0) if name in ("indexOf", "lastIndexOf")
                           else (a0 in s if name == "includes" else s.startswith(a0) if name == "startsWith"
                                 else s.endswith(a0) if name == "endsWith" else s.find(a0)))
            if name == "repeat":
                k = int(_to_num(a0) or 0)
                if k < 0 or len(s) * k > self.max_string:
                    return Val(NOVAL, tags)
                return Val(s * k, tags)
            if name in ("padStart", "padEnd"):
                w = int(_to_num(a0) or 0)
                fill = a1 if isinstance(a1, str) else " "
                if w > self.max_string or not fill:
                    return Val(NOVAL, tags)
                pad = (fill * w)[:max(0, w - len(s))]
                return Val(pad + s if name == "padStart" else s + pad, tags)
            if name in ("replace", "replaceAll"):
                if len(args) > 1 and _meta(args[1], "fn") is not None:
                    return self.replace_fn(recv, args)
                if not isinstance(a1, str):
                    return Val(NOVAL, _tags(recv, *args))
                rep_tags = _tags(recv, *args)
                if isinstance(a0, str):
                    if a0 == "":
                        return Val(a1 + s if name == "replace" else NOVAL, rep_tags)
                    if name == "replace":
                        out = s.replace(a0, a1, 1)
                    else:
                        if s.count(a0) * (len(a1) + 1) + len(s) > self.max_string:
                            return Val(NOVAL, rep_tags)
                        out = s.replace(a0, a1)
                    return self.mk(out, rep_tags)
                rx = _meta(args[0], "regex")
                if rx:
                    rep = re.sub(r"\$(\d)", r"\\\1", a1.replace("\\", "\\\\")).replace("$&", r"\g<0>")
                    count = 0 if "g" in rx[1] else 1
                    flags = re.I if "i" in rx[1] else 0
                    out = _py_regex(rx[0], flags).sub(rep, s, count=count)
                    return self.mk(out, rep_tags)
                return Val(NOVAL, rep_tags)
            if name == "match":
                return Val(NOVAL, tags)
            if name == "localeCompare":
                return Val(NOVAL)
        except (TypeError, ValueError, re.error, IndexError, OverflowError):
            return Val(NOVAL, tags)
        return None

    def replace_fn(self, recv, args):
        rx = _meta(args[0], "regex")
        s = recv.c
        fn = args[1]
        if not rx:
            return Val(NOVAL, _tags(recv))
        try:
            pat = _py_regex(rx[0], re.I if "i" in rx[1] else 0)
            out, last, count = [], 0, 0
            for m in pat.finditer(s):
                count += 1
                if count > 2000 or self.iters > self.max_iter:
                    return Val(NOVAL, _tags(recv))
                self.iters += 1
                out.append(s[last:m.start()])
                r = self.apply(fn, [Val(m.group(0))] + [Val(g if g is not None else UNDEF) for g in m.groups()],
                               None, ("call", 0))
                rs = _to_str(r.c) if r.known else None
                if rs is None:
                    return Val(NOVAL, _tags(recv, r))
                out.append(rs)
                last = m.end()
                if "g" not in rx[1]:
                    break
            out.append(s[last:])
            return self.mk("".join(out), recv.tags)
        except (re.error, TypeError):
            return Val(NOVAL, _tags(recv))

    def list_method(self, recv: Val, name, args) -> Val | None:
        items = recv.c
        tags = recv.tags
        a0 = args[0] if args else Val(UNDEF)
        if name == "join":
            if not args or a0.c is UNDEF:
                sep = ","
            elif a0.known:
                sep = _to_str(a0.c) or ""
            else:
                return Val(NOVAL, _tags(recv, a0))
            strs = []
            for x in items:
                if x.known and (x.c is None or x.c is UNDEF):
                    strs.append("")
                    continue
                s = _to_str(x.c) if x.known else None
                if s is None:
                    return self.concat(_interleave(items, Val(sep)))
                strs.append(s)
            return self.mk(sep.join(strs), _tags(recv))
        if name == "reverse":
            items.reverse()
            return recv
        if name in ("slice",):
            st = int(_to_num(a0.c) or 0) if a0.known and a0.c is not UNDEF else 0
            en = int(_to_num(args[1].c)) if len(args) > 1 and args[1].known and args[1].c is not UNDEF else len(items)
            return Val(items[st:en], tags)
        if name == "concat":
            out = list(items)
            for x in args:
                out.extend(x.c if isinstance(x.c, list) else [x])
            return self.mk(out, _tags(recv, *args))
        if name in ("push", "unshift"):
            if len(items) + len(args) < self.max_iter:
                if name == "push":
                    items.extend(args)
                else:
                    items[0:0] = args
            return Val(len(items))
        if name in ("pop", "shift"):
            return (items.pop() if name == "pop" else items.pop(0)) if items else Val(UNDEF)
        if name in ("map", "forEach", "filter", "flatMap", "some", "every", "find") and _meta(a0, "fn") is not None:
            r = self.map_items(list(items), a0, tags)
            if name == "forEach":
                return Val(UNDEF)
            if name == "filter" and isinstance(r.c, list):
                out = []
                for item, keep in zip(items, r.c):
                    if not keep.known:
                        return Val(NOVAL, _tags(recv))
                    if _truthy(keep.c):
                        out.append(item)
                return Val(out, tags)
            if name == "map":
                return r
            return Val(NOVAL, _tags(r, recv))
        if name == "map" and a0.ref:
            return self.map_items(list(items), a0, tags)
        if name == "reduce" and _meta(a0, "fn") is not None:
            acc = args[1] if len(args) > 1 else (items[0] if items else Val(UNDEF))
            rest = items if len(args) > 1 else items[1:]
            if self.iters + len(rest) > self.max_iter:
                return Val(NOVAL, _tags(recv))
            self.iters += len(rest)
            for i, x in enumerate(rest):
                acc = self.apply(a0, [acc, x, Val(i)], None, ("call", 0))
            return acc
        if name in ("includes", "indexOf"):
            return Val(NOVAL)
        if name in ("toString",):
            return self.list_method(recv, "join", [])
        if name in ("fill", "sort", "flat"):
            return recv
        return Val(NOVAL, tags)

    def bytes_method(self, recv: Val, name, args) -> Val | None:
        data = bytes(recv.c)
        a0 = args[0] if args else Val(UNDEF)
        enc = (a0.s() or "utf8").lower().replace("-", "") if a0.known and isinstance(a0.c, str) else "utf8"
        if name == "toString":
            try:
                if enc == "base64":
                    return self.mk(base64.b64encode(data).decode(), recv.tags)
                if enc == "hex":
                    return self.mk(data.hex(), recv.tags)
                if enc in ("latin1", "binary", "ascii"):
                    return self.mk(data.decode("latin-1"), recv.tags)
                if enc in ("utf16le", "ucs2"):
                    return self.mk(data.decode("utf-16-le", "replace"), recv.tags)
                return self.mk(data.decode("utf-8", "replace"), recv.tags)
            except (ValueError, TypeError):
                return Val(NOVAL, recv.tags)
        if name in ("slice", "subarray"):
            st = int(_to_num(a0.c) or 0) if a0.known and a0.c is not UNDEF else 0
            en = int(_to_num(args[1].c)) if len(args) > 1 and args[1].known else len(data)
            return Val(data[st:en], recv.tags, None, {"buf": True})
        if name == "reverse":
            return Val(data[::-1], recv.tags, None, {"buf": True})
        if name == "map" and _meta(a0, "fn") is not None:
            r = self.map_items([Val(b) for b in data], a0, recv.tags)
            if isinstance(r.c, list):
                try:
                    return Val(bytes(int(_to_num(x.c)) & 0xFF for x in r.c), recv.tags, None, {"buf": True})
                except (TypeError, ValueError):
                    pass
            return Val(NOVAL, recv.tags, None, {"buf": True})
        return Val(NOVAL, recv.tags)


# ============================================================================================================ helpers

def _interleave(items, sep):
    out = []
    for i, x in enumerate(items):
        if i:
            out.append(sep)
        out.append(x)
    return out


def _path_tags(hint: str) -> frozenset:
    """CRED_PATH / AUTOSTART_PATH for a partly known string whose known parts already name such a place."""
    if not hint or "/" not in hint.replace("\\", "/") and "currentversion" not in hint.lower():
        return frozenset()
    probe = hint.replace(PH, "x")
    cls = path_class(probe)
    if cls == "credential":
        return frozenset({CRED_PATH})
    if cls == "autostart":
        return frozenset({AUTOSTART_PATH})
    return frozenset()


def _truthy(c) -> bool:
    if c is UNDEF or c is None or c is False or c is NOVAL:
        return False
    if isinstance(c, float) and c != c:
        return False
    if isinstance(c, (int, float, str)) and not c:
        return False
    return True


def _is_strish(c) -> bool:
    return isinstance(c, (str, list, dict)) or c is UNDEF and False


def _to_num(c):
    if isinstance(c, bool):
        return int(c)
    if isinstance(c, (int, float)):
        return c
    if c is None:
        return 0
    if c is UNDEF:
        return float("nan")
    if isinstance(c, str):
        t = c.strip()
        if not t:
            return 0
        try:
            if t[:2].lower() == "0x":
                return int(t, 16)
            f = float(t)
            return int(f) if f.is_integer() and "." not in t and "e" not in t.lower() else f
        except ValueError:
            return float("nan")
    return None


def _int32(x) -> int:
    try:
        if isinstance(x, float):
            if x != x or x in (float("inf"), float("-inf")):
                return 0
            x = int(x)
    except (ValueError, OverflowError):
        return 0
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x & 0x80000000 else x


def _js_mod(x, y):
    if y == 0:
        return float("nan")
    import math
    r = math.fmod(x, y)
    return int(r) if isinstance(x, int) and isinstance(y, int) else r


def _js_eq(x, y) -> bool:
    if isinstance(x, (list, dict)) or isinstance(y, (list, dict)):
        return x is y
    if isinstance(x, bool) or isinstance(y, bool):
        return x is y if isinstance(x, bool) and isinstance(y, bool) else x == y
    return x == y


def _to_str(c) -> str | None:
    if isinstance(c, str):
        return c
    if isinstance(c, bool):
        return "true" if c else "false"
    if isinstance(c, (int, float)):
        return _num_str(c)
    if c is None:
        return "null"
    if c is UNDEF:
        return "undefined"
    if isinstance(c, (bytes, bytearray)):
        return bytes(c).decode("utf-8", "replace")
    if isinstance(c, list):
        out = []
        for x in c[:10000]:
            if not x.known:
                return None
            if x.c is None or x.c is UNDEF:
                out.append("")
                continue
            s = _to_str(x.c)
            if s is None:
                return None
            out.append(s)
        return ",".join(out)
    if isinstance(c, dict):
        return "[object Object]"
    return None


def _to_py(v: Val, depth=0):
    if depth > 20 or not v.known:
        return NOVAL
    c = v.c
    if c is UNDEF:
        return None
    if isinstance(c, list):
        out = [_to_py(x, depth + 1) for x in c]
        return NOVAL if any(x is NOVAL for x in out) else out
    if isinstance(c, dict):
        out = {k: _to_py(x, depth + 1) for k, x in c.items()}
        return NOVAL if any(x is NOVAL for x in out.values()) else out
    if isinstance(c, (bytes, bytearray)):
        return {"type": "Buffer", "data": list(c)}
    return c


def _from_py(x, tags=frozenset(), depth=0) -> Val:
    if depth > 30:
        return Val(NOVAL, tags)
    if isinstance(x, list):
        return Val([_from_py(i, tags, depth + 1) for i in x], tags)
    if isinstance(x, dict):
        return Val({str(k): _from_py(i, tags, depth + 1) for k, i in x.items()}, tags)
    return Val(x, tags)


def _radix(n, radix) -> str:
    if not isinstance(n, int) or not (2 <= radix <= 36):
        return _num_str(n)
    digits = "0123456789abcdefghijklmnopqrstuvwxyz"
    if n == 0:
        return "0"
    neg, n = n < 0, abs(n)
    out = []
    while n:
        n, r = divmod(n, radix)
        out.append(digits[r])
    return ("-" if neg else "") + "".join(reversed(out))


def _py_regex(src: str, flags: int = 0) -> re.Pattern:
    """A JavaScript regex body as a Python pattern (named groups and \\d style escapes match; the rest is close enough).
    Raises re.error when Python cannot read it."""
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return re.compile(re.sub(r"\(\?<([A-Za-z_]\w*)>", r"(?P<\1>", src).replace("\\/", "/"), flags)


def _quote(v: Val) -> str:
    s = _to_str(v.c) if v.known else None
    if s is None:
        s = (_meta(v, "partial") or PH).replace(PH, "?")
    if s and re.fullmatch(r"[\w@%+=:,./~-]+", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


# ============================================================================================================== entry

def analyze_source(ctx, text: str, file: str, phase: str, depth: int = 0, line_base: int | None = None) -> None:
    """Facts of one JavaScript source into ctx. Raises only LimitExceeded (the caller records the file as not analyzed);
    any other failure ends the analysis of this source quietly with what was found so far."""
    if not isinstance(text, str) or depth > int(ctx.limits["max_depth"]):
        return
    if len(text) > int(ctx.limits["max_string"]):
        raise LimitExceeded("size limit")
    try:
        stmts = parse(text, ctx.check_time)
    except LimitExceeded:
        raise
    except (RecursionError, Exception):               # noqa: BLE001 - parse() already recovers per statement
        return
    an = Analyzer(ctx, text, file, phase, depth, line_base)
    try:
        an.run(stmts)
    except LimitExceeded:
        raise
    except (RecursionError, Exception):               # noqa: BLE001
        return


__all__ = ["analyze_source", "parse", "lex", "Analyzer"]
