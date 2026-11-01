"""Behavior verdict (guard/behavior): what the package's code DOES, and when, decided by a policy table.

The front ends never run the code. They rebuild values (constant folding, decoders, assembled names) and follow where
data flows (network response -> exec, credential file -> network send ...), then leave facts ("findings") here:

  python.py   Python (standard library ast)          js.py     JavaScript (own tokenizer, no external parser)
  shell.py    shell / PowerShell / cmd command lines (also the commands Python and JavaScript run)

Each fact carries the phase it runs at:
  install            the root setup.py of an sdist, an npm install script and the files it runs
  interpreter_start  a .pth import line, a root sitecustomize / usercustomize
  import             module top level, and the functions it calls (JavaScript: outside functions, IIFEs, called ones)
  call               code that runs only if something calls it
  command            a script run by hand: a shell script, a package's __main__.py, an `if __name__ == "__main__"` block
rules/behavior.json "findings" maps (finding, phase) to block / review / null. Evidence is kept for every fact; the two
features `behavior_block` / `behavior_review` carry the verdict to the hard rules (rules/scoring.json).

Test and maintenance files (rules/signals.json paths) are held back, not dropped: one that code running at install,
interpreter start or import reaches (an import, a .pth line, setup.py, the in-tree build backend of pyproject.toml, a
hook command naming it) is read at the phase of what reached it.

analyze() never raises: a file over a limit (rules/behavior.json "limits") is recorded as not analyzed and skipped; one
that would run at install, interpreter start or import is a finding of its own (not_analyzed).
"""
from __future__ import annotations

import codecs
import re
import time
from pathlib import Path

from .values import norm_path, policy

ACTION_ORDER = {"block": 0, "review": 1, None: 2}
SHELL_SUFFIXES = (".sh", ".bash")


class LimitExceeded(Exception):
    """A file went over a limit of rules/behavior.json; what was found before stays, the rest of the file is skipped."""


class Context:
    """What the front ends share for one package: the facts found, the files the code downloads, the limits."""

    def __init__(self, deadline: float | None = None):
        self.pol = policy()
        self.limits = self.pol.limits
        self.deadline = deadline if deadline is not None else time.monotonic() + float(self.limits["seconds"])
        self.facts: dict[tuple, str] = {}          # (finding, phase, file, line) -> detail
        self.downloaded: set[str] = set()          # paths the code writes fetched data to (normalized)
        self.executable: set[str] = set()
        self.modules: dict[str, tuple] = {}        # python: dotted module name -> (path, rel)  (local imports)
        self.module_phases: set[tuple] = set()     # (rel, phase) analyzed already
        self.py_scopes: dict[tuple, object] = {}   # python: (rel, phase) -> the module's interpreter (its globals)
        self.py_pending: list = []                 # python: interpreters whose uncalled functions are still to read
        self.not_analyzed: list[tuple[str, str]] = []
        self.by_rel: dict[str, Path] = {}         # every file given, by its package-relative name
        self.held: set[str] = set()               # test / maintenance files read only when something reaches them
        self.pkg_root: Path | None = None         # the package root folder of the files given
        self._aside: dict[str, Path] | None = None
        self._left: set[str] = set()

    def unread(self, rel: str, phase: str, why: str) -> None:
        """A file not (fully) analyzed; one that runs by itself (install, interpreter start, import) is a finding.
        The time limit is not: it depends on the machine and its load, and large real packages reach it."""
        self.not_analyzed.append((rel, why))
        if phase in self.pol.auto and not why.startswith("time limit"):
            self.emit("not_analyzed", phase, rel, 0, why)

    # ---------------------------------------------------------------- facts
    def emit(self, finding: str, phase: str, file: str, line, detail) -> None:
        if finding not in self.pol.findings:
            raise KeyError(f"behavior.json has no finding '{finding}'")
        key = (finding, phase, file, int(line or 0))
        if key not in self.facts:
            self.facts[key] = " ".join(str(detail or "").split())[:300]

    def check_time(self) -> None:
        if time.monotonic() > self.deadline:
            raise LimitExceeded("time limit")

    # ---------------------------------------------------------------- downloaded files
    @staticmethod
    def _norm(path) -> str:
        p = norm_path(str(path or ""))
        return re.sub(r"^(\./)+", "", p)

    def add_downloaded(self, path) -> None:
        if isinstance(path, str) and path.strip():
            self.downloaded.add(self._norm(path))

    def was_downloaded(self, path) -> bool:
        if not isinstance(path, str) or not path.strip():
            return False
        n = self._norm(path)
        known = {self._norm(d) for d in self.downloaded}
        if n in known:
            return True
        base = n.rsplit("/", 1)[-1]
        return len(base) > 2 and any(d.rsplit("/", 1)[-1] == base for d in known)

    def mark_executable(self, path) -> None:
        if isinstance(path, str):
            self.executable.add(self._norm(path))

    # ---------------------------------------------------------------- code inside code
    def nested_python(self, code, phase, file, line, depth, env=None) -> None:
        from . import python
        if isinstance(code, (bytes, bytearray)):
            code = bytes(code).decode("utf-8", "replace")
        if not isinstance(code, str) or depth > self.limits["max_depth"]:
            return
        python.analyze_source(self, code, file, phase, depth=depth, line_base=line, env=env)

    def nested_js(self, code, phase, file, line, depth) -> None:
        from . import js
        if isinstance(code, (bytes, bytearray)):
            code = bytes(code).decode("utf-8", "replace")
        if not isinstance(code, str) or depth > self.limits["max_depth"]:
            return
        js.analyze_source(self, code, file, phase, depth=depth, line_base=line)

    def shell(self, text, phase, file, line, depth=0) -> dict:
        from . import shell
        return shell.analyze(text, self, phase, file, line, depth)

    # ---------------------------------------------------------------- files of the package that are not planned
    def _side(self) -> dict[str, Path]:
        """The package's other small files (safe_extract keeps them aside for an sdist); self._left gets the ones that
        were too large for that."""
        if self._aside is None:
            self._aside = {}
            root = self.pkg_root
            for i, part in enumerate(root.parts if root is not None else ()):
                if not part.endswith(".unpacked"):
                    continue
                import safe_extract
                base = safe_extract.aside_dir(Path(*root.parts[:i + 1]))
                twin = base.joinpath(*root.parts[i + 1:])
                above = len(root.parts) - i - 1          # the archive's own top folder above the package root
                try:
                    for f in twin.rglob("*") if twin.is_dir() else ():
                        if len(self._aside) >= 20000:
                            break
                        if f.is_file():
                            self._aside.setdefault(f.relative_to(twin).as_posix(), f)
                    left = base.with_name(base.name + ".left")
                    for ln in (left.read_text(errors="replace").splitlines() if left.is_file() else ()):
                        parts = ln.strip().split("/")
                        if len(parts) > above:
                            self._left.add("/".join(parts[above:]))
                except OSError:
                    pass
                break
        return self._aside

    def bundled(self, rel: str) -> tuple[str, Path | None]:
        """("file" | "aside", path) for a file the package ships, ("left", None) for one shipped but too large to keep,
        ("absent", None) otherwise. rel: package-relative ("./" and "a/.." folded)."""
        rel = norm_rel(rel)
        if not rel:
            return "absent", None
        if rel in self.by_rel:
            return "file", self.by_rel[rel]
        aside = self._side()
        if rel in aside:
            return "aside", aside[rel]
        return ("left", None) if rel in self._left else ("absent", None)

    def bundled_tail(self, tail: str) -> list[tuple[str, Path]]:
        """[(rel, path)] of the files whose path ends with `tail` (a path whose leading folders are unknown)."""
        tail = norm_rel(tail)
        if not tail:
            return []
        out = []
        for rel, path in list(self.by_rel.items()) + list(self._side().items()):
            if rel == tail or rel.endswith("/" + tail):
                out.append((rel, path))
        return out[:4]

    def read_python(self, path: Path, rel: str, phase: str) -> str | None:
        """A Python file's text as the interpreter reads it (its PEP 263 encoding), None over the size limit. A declared
        encoding that rewrites ASCII (utf-7, unicode_escape ...) hides code from every reader that assumes UTF-8."""
        try:
            if path.stat().st_size > int(self.limits["max_file_bytes"]):
                return None
            raw = path.read_bytes()
        except OSError:
            return None
        text, codec = decode_python(raw)
        if codec:
            self.emit("encoded_source", phase, rel, 1, f"source encoding declared as {codec}")
        return text

    def run_file(self, rel: str, path: Path, lang: str, phase: str) -> bool:
        """A package file that code being analyzed runs (a script setup.py starts, a file it exec()s): read at that
        phase, once. False if it could not be read (over the size limit, unreadable)."""
        from . import python
        key = (rel, phase)
        if key in self.module_phases:
            return True
        self.module_phases.add(key)
        if lang == "python":
            text = self.read_python(path, rel, phase)
        else:
            text = _read(path, int(self.limits["max_file_bytes"]))
        if text is None:
            return False
        try:
            if lang == "python":
                python.analyze_source(self, text, rel, phase, loaded=True)
            elif lang == "make":
                self.shell(make_recipes(text), phase, rel, 1)
            elif lang == "cmake":
                self.shell(cmake_commands(text), phase, rel, 1)
            else:
                self.shell(text, phase, rel, 1)
        except LimitExceeded as e:
            self.unread(rel, phase, str(e))
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            pass
        return True


# -------------------------------------------------------------------------------------------- reading files

_CODING = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_PROBE = b"a\\x41\\u0041+AGE-~{}"


def decode_python(raw: bytes) -> tuple[str, str | None]:
    """(text, codec) of Python source: decoded with the encoding its first two lines declare (PEP 263); codec is set
    only when that encoding rewrites plain ASCII text (utf-7, unicode_escape, raw_unicode_escape, a non-text codec)."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", "replace"), None
    lines = raw.split(b"\n", 2)
    m = _CODING.match(lines[0])
    if m is None and len(lines) > 1 and (not lines[0].strip() or lines[0].lstrip().startswith(b"#")):
        m = _CODING.match(lines[1])
    if m is None:
        return raw.decode("utf-8", "replace"), None
    name = m.group(1).decode("ascii", "replace")
    try:
        info = codecs.lookup(name)
    except LookupError:
        return raw.decode("utf-8", "replace"), None
    if info.name in ("utf-8", "ascii", "latin-1", "iso8859-1"):
        return raw.decode(info.name, "replace"), None
    if not getattr(info, "_is_text_encoding", True):
        return raw.decode("utf-8", "replace"), name     # Python refuses it as source; still an attempt to hide code
    try:
        rewrites = codecs.decode(_PROBE, info.name, "strict") != _PROBE.decode("ascii")
    except Exception:                                    # noqa: BLE001 - a codec that cannot read ASCII rewrites it
        rewrites = True
    try:
        text = codecs.decode(raw, info.name, "replace")
    except Exception:                                    # noqa: BLE001
        text = raw.decode("utf-8", "replace")
    return text, (name if rewrites else None)


def norm_rel(p: str) -> str:
    """A package-relative path with "./", empty parts and "a/.." folded; "" if it leaves the package."""
    out: list[str] = []
    for part in str(p or "").replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not out:
                return ""
            out.pop()
        else:
            out.append(part)
    return "/".join(out)


def make_recipes(text: str) -> str:
    """The shell commands of a Makefile: recipe lines and $(shell ...) calls (the parts make hands to the shell)."""
    out = []
    for ln in text.replace("\\\n", " ").splitlines():
        if ln.startswith("\t"):
            out.append(ln.strip().lstrip("@-+"))
        out += re.findall(r"\$\(shell\s+([^)]*)\)", ln)
    return "\n".join(out)


_CMAKE_KEYWORDS = re.compile(r"\b(WORKING_DIRECTORY|OUTPUT_VARIABLE|RESULT_VARIABLE|ERROR_VARIABLE|DEPENDS|COMMENT|VERBATIM|"
                             r"OUTPUT_QUIET|ERROR_QUIET|BYPRODUCTS|OUTPUT|ALL|TIMEOUT|USES_TERMINAL)\b")


def cmake_commands(text: str) -> str:
    """The commands a CMake file runs: the COMMAND arguments of execute_process / add_custom_command /
    add_custom_target, and file(DOWNLOAD url path) as a fetch."""
    out = []
    for m in re.finditer(r"\b(?:execute_process|add_custom_command|add_custom_target)\s*\((.*?)\)\s*(?:\n|$)", text, re.S | re.I):
        for cmd in re.split(r"\bCOMMAND\b", m.group(1))[1:]:
            out.append(" ".join(_CMAKE_KEYWORDS.split(cmd)[0].split()))
    for m in re.finditer(r"\bfile\s*\(\s*DOWNLOAD\s+\"?([^\s\")]+)\"?\s+\"?([^\s\")]+)", text, re.I):
        out.append(f"curl -o {m.group(2)} {m.group(1)}")
    return "\n".join(out)


# -------------------------------------------------------------------------------------------- choosing files and phases

def _lang(rs, rule_engine, path: Path) -> str | None:
    if path.suffix in (".py", ".pth"):
        return "python"
    if path.name.startswith("package.json#"):
        return "js" if path.suffix == ".js" else "shell"
    lang = rule_engine.lang_of(rs, path)
    return lang if lang in ("js", "shell") else None


def plan(files: list[Path], features) -> list[tuple[Path, str, str, str]]:
    """[(path, package-relative name, language, phase)] of the files to read, install-time ones first."""
    return _plan(files, features)[0]


def _plan(files: list[Path], features, ctx: Context | None = None) -> tuple[list, list]:
    """(the files to read - see plan(), the test / maintenance files held back, in the same form). A held file that a
    hook command or the in-tree build backend names is read like any other."""
    import rule_engine
    rs = rule_engine.current()
    eco = rs.ecosystems.get(getattr(features, "ecosystem", None) or "pypi") or rs.ecosystems["pypi"]
    code_langs = set(eco["code"])
    dev_names = eco.get("dev_names")
    install_setups = rule_engine.install_time_setups(rs, files)
    install_files = [str(f).replace("\\", "/") for f in (getattr(features, "install_time_files", None) or [])]
    out, held = [], []
    for path in files:
        try:
            if not path.is_file():
                continue
        except OSError:
            continue
        lang = _lang(rs, rule_engine, path)
        if lang is None:
            continue
        rel = rule_engine.package_relative(path).replace("\\", "/")
        lifecycle = path.name.startswith("package.json#")
        run_by_install = lifecycle or any(rel == f or rel.endswith("/" + f) for f in install_files)
        if lang not in code_langs and not run_by_install:
            continue
        site_root = rule_engine.archive_depth(path) == 1 or rule_engine.at_site_root(path)
        if lang == "python":
            if path in install_setups:
                phase = "install"
            elif path.suffix == ".pth":
                if not site_root:
                    continue
                phase = "interpreter_start"
            elif site_root and path.name in rs.startup_py:
                phase = "interpreter_start"
            elif path.name == "setup.py":
                continue                                     # a nested setup.py does not run on install
            elif run_by_install:
                phase = "install"
            elif path.name == "__main__.py":
                phase = "command"                            # runs on `python -m pkg`, not when the package is imported
            else:
                phase = "import"
        elif run_by_install:
            phase = "install"
        else:
            phase = "import" if lang == "js" else "command"
        if phase in ("import", "command") and (rule_engine.is_test_path(rs, path)
                                               or rule_engine.is_dev_path(rs, path, set(dev_names) if dev_names else None)):
            held.append((path, rel, lang, phase))
            continue
        out.append((path, rel, lang, phase))
    backend = _build_backend(ctx, out + held) if ctx is not None else set()
    # command lines that run files: install scripts, and in a bundle (a plugin, a hook) every script and hook command
    bundle = getattr(features, "ecosystem", None) == "bundle"
    texts = [p for p, _rel, lang, ph in out if lang == "shell" and (bundle or ph == "install")]
    if bundle:                                           # a hook's command line kept as a text of its own
        texts += [p for p in files if not p.suffix and "/" not in rule_engine.package_relative(p)]
    named = _named_by_commands(texts, held)
    if backend or named:
        out += [item for item in held if item[1] in backend or item[1] in named]
        held = [item for item in held if not (item[1] in backend or item[1] in named)]
        out = [(p, rel, lang, "install" if rel in backend else ph) for p, rel, lang, ph in out]
    order = {"install": 0, "interpreter_start": 1, "import": 2, "command": 3, "call": 4}
    # import roots (what `import pkg` runs first, and what it imports from there) before the rest: files left over at
    # the file-count limit are ones only an explicit import of that very module runs
    out.sort(key=lambda x: (order.get(x[3], 9), not import_root(x[1]), x[1].count("/"), x[1]))
    return out, held


def import_root(rel: str) -> bool:
    """A top-level module or a top-level package's __init__.py (below src/, lib/ or a wheel's .data/purelib|platlib/)."""
    parts = rel.split("/")
    if len(parts) > 2 and parts[0].endswith(".data") and parts[1] in ("purelib", "platlib"):
        parts = parts[2:]
    elif len(parts) > 1 and parts[0] in ("src", "lib", "python"):
        parts = parts[1:]
    return len(parts) == 1 or (len(parts) == 2 and parts[1].startswith("__init__."))


_CMD_PATH = re.compile(r"[\w./${}\\:-]+\.(?:py|js|mjs|cjs|ts|sh|bash|ps1)\b")


def _named_by_commands(texts: list[Path], held) -> set[str]:
    """Held files a command text (a hook's command line, a shell script) names: `python3 ${CLAUDE_PLUGIN_ROOT}/tests/run.py`."""
    if not held:
        return set()
    names = {rel: rel.split("/") for _p, rel, _l, _ph in held}
    out = set()
    for path in texts:
        for tok in _CMD_PATH.findall(_read(path, 256 * 1024) or ""):
            parts = [x for x in tok.replace("\\", "/").split("/") if x not in ("", ".")]
            out |= {rel for rel, rp in names.items() if len(rp) <= len(parts) and parts[-len(rp):] == rp}
    return out


def _build_backend(ctx: Context, items) -> set[str]:
    """The files of an in-tree PEP 517 build backend (pyproject.toml build-backend + backend-path): pip imports it to
    build the package, so it runs at install like setup.py."""
    _status, path = ctx.bundled("pyproject.toml")
    if path is None:
        return set()
    text = _read(path, 1024 * 1024) or ""
    try:
        import tomllib
        bs = tomllib.loads(text).get("build-system") or {}
    except Exception:                                    # noqa: BLE001 - not TOML (or no tomllib): read it roughly
        bs = {}
        m = re.search(r"^\s*build-backend\s*=\s*[\"']([^\"']+)", text, re.M)
        if m:
            bs["build-backend"] = m.group(1)
        m = re.search(r"^\s*backend-path\s*=\s*\[([^\]]*)\]", text, re.M)
        if m:
            bs["backend-path"] = re.findall(r"[\"']([^\"']*)[\"']", m.group(1))
    backend, dirs = bs.get("build-backend"), bs.get("backend-path")
    if not isinstance(backend, str) or not isinstance(dirs, list):
        return set()                                     # no backend-path: the backend is an installed package
    mod = backend.split(":", 1)[0].strip().replace(".", "/")
    rels = {rel for _p, rel, lang, _ph in items if lang == "python"}
    out = set()
    for d in dirs:
        base = norm_rel(d) if isinstance(d, str) else ""
        for cand in (f"{mod}.py", f"{mod}/__init__.py"):
            rel = norm_rel(f"{base}/{cand}")
            if rel in rels:
                out.add(rel)
    return out


def _module_index(planned) -> dict[str, tuple]:
    """Python files by the dotted module name they are imported as: the path from the package root, also without a
    leading src/ or lib/ folder or a wheel's <dist>.data/purelib|platlib/ prefix."""
    idx: dict[str, tuple] = {}
    for path, rel, lang, _phase in planned:
        if lang != "python" or path.suffix != ".py":
            continue
        parts = rel[:-3].split("/")
        if parts[-1] == "__init__":
            parts = parts[:-1]
        variants = [parts]
        if len(parts) > 2 and parts[0].endswith(".data") and parts[1] in ("purelib", "platlib"):
            variants.append(parts[2:])
        if len(parts) > 1 and parts[0] in ("src", "lib", "python"):
            variants.append(parts[1:])
        for v in variants:
            name = ".".join(v)
            if name and name not in idx:
                idx[name] = (path, rel)
    return idx


def _read(path: Path, limit: int) -> str | None:
    try:
        if path.stat().st_size > limit:
            return None
        return path.read_text(errors="replace")
    except OSError:
        return None


def analyze_files(files: list[Path], features, deadline: float | None = None) -> Context:
    """Run the front ends over the package files; returns the Context with the facts. Never raises."""
    from . import js, python
    ctx = Context(deadline)
    lim = ctx.limits
    try:
        import rule_engine
        for f in files:
            rel = rule_engine.package_relative(f).replace("\\", "/")
            if rel not in ctx.by_rel and f.is_file():
                ctx.by_rel[rel] = f
                if ctx.pkg_root is None and rule_engine.archive_depth(f):
                    ctx.pkg_root = f.parents[len(rel.split("/")) - 1]
        planned, held = _plan(files, features, ctx)
    except Exception as e:                                   # noqa: BLE001 - the guard must keep going
        ctx.not_analyzed.append(("*", f"file selection failed: {type(e).__name__}"))
        return ctx
    ctx.held = {rel for _p, rel, _l, _ph in held}
    ctx.modules = _module_index(planned + held)
    for n, (path, rel, lang, phase) in enumerate(planned):
        over = n >= int(lim["max_files"])
        if over or time.monotonic() > ctx.deadline:
            why = f"only the first {lim['max_files']} files analyzed" if over else f"time limit ({lim['seconds']}s)"
            rest = [(r, ph) for _p, r, _l, ph in planned[n:] if (r, ph) not in ctx.module_phases]
            ctx.not_analyzed.append(("*", f"{why}: {len(rest)} files not analyzed"))
            for r, ph in rest:              # left over at the file-count limit: install / startup files and import roots
                if over and (ph in ("install", "interpreter_start") or ph == "import" and import_root(r)):
                    ctx.emit("not_analyzed", ph, r, 0, why)
            break
        if (rel, phase) in ctx.module_phases:
            continue
        text = ctx.read_python(path, rel, phase) if lang == "python" else _read(path, int(lim["max_file_bytes"]))
        if text is None:
            ctx.unread(rel, phase, "size limit")
            continue
        try:
            if lang == "python":
                if path.suffix == ".pth":
                    text = "\n".join(ln for ln in text.splitlines() if ln.startswith(("import ", "import\t")))
                ctx.module_phases.add((rel, phase))
                python.analyze_source(ctx, text, rel, phase)
            elif lang == "js":
                js.analyze_source(ctx, text, rel, phase)
            else:
                ctx.shell(text, phase, rel, 1)
        except LimitExceeded as e:
            ctx.unread(rel, phase, str(e))
        except (RecursionError, MemoryError):
            ctx.unread(rel, phase, "depth limit")
        except Exception as e:                               # noqa: BLE001 - one bad file must not stop the scan
            ctx.not_analyzed.append((rel, f"analysis failed: {type(e).__name__}"))
    try:
        python.finish(ctx)
    except Exception as e:                                   # noqa: BLE001
        ctx.not_analyzed.append(("*", f"analysis failed: {type(e).__name__}"))
    return ctx


def analyze(files: list[Path], features) -> None:
    """Behavior facts of the unpacked package into `features`: evidence (rule = finding id, with phase and label),
    behavior_block / behavior_review from the policy table, behavior_not_analyzed for files over a limit."""
    import rule_engine
    rs = rule_engine.current()
    try:
        ctx = analyze_files(files, features)
    except Exception as e:                                   # noqa: BLE001
        features.behavior_not_analyzed = [("*", f"analysis failed: {type(e).__name__}")]
        return
    pol = ctx.pol
    rows = []
    for (finding, phase, file, line), detail in ctx.facts.items():
        rows.append((ACTION_ORDER.get(pol.action(finding, phase), 2), finding, phase, file, line, detail))
    rows.sort()                                             # block facts first: the per-rule evidence cap keeps them
    for rank, finding, phase, file, line, detail in rows:
        action = pol.action(finding, phase)
        if action == "block":
            features.behavior_block = True
        elif action == "review":
            features.behavior_review = True
        if sum(1 for e in features.evidence if e["rule"] == finding) >= rs.max_evidence:
            continue
        f = pol.findings[finding]
        features.evidence.append({"rule": finding, "file": file, "line": line or 1, "snippet": detail[:rs.snippet_max],
                                  "phase": phase, "action": action, "label": f["label"], "text": f["text"]})
    features.behavior_not_analyzed = ctx.not_analyzed[:20]


__all__ = ["analyze", "analyze_files", "plan", "Context", "LimitExceeded"]
