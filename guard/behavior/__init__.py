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

analyze() never raises: a file over a limit (rules/behavior.json "limits") is recorded as not analyzed and skipped.
"""
from __future__ import annotations

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
    import rule_engine
    rs = rule_engine.current()
    eco = rs.ecosystems.get(getattr(features, "ecosystem", None) or "pypi") or rs.ecosystems["pypi"]
    code_langs = set(eco["code"])
    dev_names = eco.get("dev_names")
    install_setups = rule_engine.install_time_setups(rs, files)
    install_files = [str(f).replace("\\", "/") for f in (getattr(features, "install_time_files", None) or [])]
    out = []
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
            continue
        out.append((path, rel, lang, phase))
    order = {"install": 0, "interpreter_start": 1, "import": 2, "command": 3, "call": 4}
    out.sort(key=lambda x: (order.get(x[3], 9), x[1]))
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
        planned = plan(files, features)
    except Exception as e:                                   # noqa: BLE001 - the guard must keep going
        ctx.not_analyzed.append(("*", f"file selection failed: {type(e).__name__}"))
        return ctx
    ctx.modules = _module_index(planned)
    for n, (path, rel, lang, phase) in enumerate(planned):
        if n >= int(lim["max_files"]):
            ctx.not_analyzed.append(("*", f"only the first {lim['max_files']} files analyzed"))
            break
        if time.monotonic() > ctx.deadline:
            ctx.not_analyzed.append(("*", f"time limit ({lim['seconds']}s): {len(planned) - n} files not analyzed"))
            break
        if (rel, phase) in ctx.module_phases:
            continue
        text = _read(path, int(lim["max_file_bytes"]))
        if text is None:
            ctx.not_analyzed.append((rel, "size limit"))
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
            ctx.not_analyzed.append((rel, str(e)))
        except (RecursionError, MemoryError):
            ctx.not_analyzed.append((rel, "depth limit"))
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
