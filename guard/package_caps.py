"""
AegisPilot - what a package's code can do (its capabilities), for the attack paths.

A verdict reason ("an OAST address is in the code") is not a capability. A capability is what the code itself does:
read or write a file, read the environment, open a network connection, run a process or a shell - with its target when
it is written as a literal, and WHEN it runs:

  install            the root setup.py of an sdist (runs during `pip install`)
  interpreter_start  a .pth import line or a root sitecustomize/usercustomize (runs every time Python starts)
  import             module-level code (runs when the package is imported)
  call               code inside a function (runs only if something calls it)

  command            a script in another language that runs when it is run (an npm bin, a hook script)

One extractor per language (not only Python):
  python   the Profile analyzer (guard/profile/analyzer.py: AST only, nothing is imported or run)
  others   the patterns of rules/capabilities.json "code_patterns" (js, shell today): line by line on the code view
           (comments and printed strings blanked, rule_engine.code_view). A new language = patterns there.
For JavaScript / shell the phase is "install" for npm install scripts and the files they run (install_files), else
top-level JavaScript = "import", indented = "call", a shell script = "command".
This module picks the files, gives each its phase, and keeps a compact, de-duplicated list for the guard record. Dynamic
code (exec/eval of something the analyzer cannot follow) is kept as its own capability, `dynamic_code`.
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import time
from pathlib import Path

GUARD = Path(__file__).resolve().parent
MAX_FILES = 3000
MAX_FILE_BYTES = 1_000_000
MAX_SECONDS = 10.0
MAX_KEPT = 60                       # capabilities kept in the record (sensitive targets and early phases first)
PHASE_ORDER = {"install": 0, "interpreter_start": 1, "import": 2, "command": 3, "call": 4}
KIND_ORDER = {"process_execute": 0, "shell_execute": 0, "dynamic_code": 1, "network_connect": 2, "file_read": 3,
              "file_write": 4, "file_delete": 5, "environment_read": 6, "environment_write": 7}
# environment reads that matter for a path: secret-looking names, or the whole environment (target unknown).
# Ordinary settings (RATE_LIMIT, WORLD_SIZE ...) are most of what packages read and say nothing about an attack.
_SECRET_ENV = __import__("re").compile(
    r"(^|_)(API_?KEY|ACCESS_KEY|SECRET(_KEY)?|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIALS?|PRIVATE_KEY|COOKIE)(_|$)"
    r"|^(AWS_|GITHUB_TOKEN|GH_TOKEN|OPENAI_|ANTHROPIC_|HF_TOKEN|NPM_TOKEN|PYPI_|TWINE_|DATABASE_URL)", __import__("re").I)


def _called_at_module_level(source: str) -> set[str]:
    """Names of functions the module calls at its top level (`def f(): ...` then `f()`): their code runs on import."""
    import ast
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return set()
    out = set()
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                out.add(node.func.id)
    return out


def _keep(c: dict) -> bool:
    if c["kind"] in ("environment_read", "environment_write"):
        return c.get("target") is None or bool(_SECRET_ENV.search(str(c.get("target"))))
    return True


def _analyzer():
    """guard/profile is loaded under its own name: as a top-level `profile` it would shadow the standard library module."""
    mod = sys.modules.get("aegis_profile.analyzer")
    if mod is not None:
        return mod
    pkg_spec = importlib.util.spec_from_file_location("aegis_profile", GUARD / "profile" / "__init__.py",
                                                      submodule_search_locations=[str(GUARD / "profile")])
    pkg = importlib.util.module_from_spec(pkg_spec)
    sys.modules["aegis_profile"] = pkg
    pkg_spec.loader.exec_module(pkg)
    spec = importlib.util.spec_from_file_location("aegis_profile.analyzer", GUARD / "profile" / "analyzer.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["aegis_profile.analyzer"] = mod
    spec.loader.exec_module(mod)
    return mod


def _phase(rs, rule_engine, path: Path, install_setups: set) -> str | None:
    if path in install_setups:
        return "install"
    site_root = rule_engine.archive_depth(path) == 1 or rule_engine.at_site_root(path)   # incl. <dist>.data/purelib
    if path.suffix == ".pth" and site_root:
        return "interpreter_start"
    if path.suffix == ".py" and site_root and path.name in rs.startup_py:
        return "interpreter_start"
    if path.suffix != ".py" or path.name == "setup.py":
        return None                     # a nested setup.py does not run on install; other files are not Python code
    if rule_engine.is_test_path(rs, path) or rule_engine.is_dev_path(rs, path):
        return None
    return "import"


_PATTERNS: dict | None = None


def patterns() -> dict:
    """{language: [(kind, compiled regex, target)]} from rules/capabilities.json "code_patterns"."""
    global _PATTERNS
    if _PATTERNS is None:
        import re
        from attack_path import _CAPS
        _PATTERNS = {lang: [(k, re.compile(rx), t) for k, rx, t in rows]
                     for lang, rows in (_CAPS.get("code_patterns") or {}).items() if lang != "about"}
    return _PATTERNS


def _home_target(literals: str) -> str:
    import re
    parts = re.findall(r"""['"`]([^'"`]+)['"`]""", literals)
    return "~/" + "/".join(x.strip("/") for x in parts)


def _norm_target(t: str) -> str:
    import re
    return re.sub(r"^(?:\$HOME|\$\{HOME\})(?=/)", "~", t)


def _pattern_file(rs, rule_engine, lang: str, path: Path, text: str, phase: str) -> list[dict]:
    """Capabilities of one non-Python file from the language's patterns: [{kind, target, when, _line, path_categories}]."""
    lines = text.splitlines()
    view = rule_engine.code_view(rs, lang, lines) or lines
    out = []
    for no, line in enumerate(view, 1):
        if not line.strip():
            continue
        when = phase
        if phase == "import" and line[:1] in (" ", "\t"):
            when = "call"                       # inside a function / callback: runs only if something calls it
        done = set()
        for kind, rx, how in patterns().get(lang, []):
            if kind in done:
                continue
            m = rx.search(line)
            if not m:
                continue
            done.add(kind)
            target = None
            if how == "home":
                target = _home_target(m.group(1))
            elif how is not None and m.group(how):
                target = _norm_target(m.group(how).strip())
            out.append({"kind": kind, "target": target, "when": when, "_line": no, "confidence": "medium",
                        "path_categories": _analyzer().path_categories(target) if target and kind.startswith("file_") else []})
            if kind == "process_execute" and target and lang != "shell" and "shell" in patterns():
                for c in _pattern_file(rs, rule_engine, "shell", path, target, when):   # execSync('curl … | sh')
                    if c["kind"] != "process_execute" or c["target"] != target:
                        out.append(dict(c, _line=no))
    return out


def _other_phase(rs, rule_engine, lang: str, path: Path, install_files) -> str | None:
    rel = rule_engine.package_relative(path).replace("\\", "/")
    if "package.json#" in path.name or any(rel == f or rel.endswith("/" + f) for f in install_files):
        return "install"                        # an npm install script, or a file one of them runs
    if rule_engine.is_test_path(rs, path) or rule_engine.is_dev_path(rs, path):
        return None
    return "import" if lang == "js" else "command"


def _pth_source(text: str) -> str:
    """The lines Python executes from a .pth file (the ones starting with `import`), as one module."""
    return "\n".join(line for line in text.splitlines() if line.startswith(("import ", "import\t")))


def extract(files: list[Path], deadline: float | None = None, install_files=()) -> dict:
    """{"items": [...], "counts": {kind: n}, "files": analyzed, "limits": [...]} for the unpacked package files.
    install_files: package-relative files the install scripts run (npm: sources/npm.install_time_files)."""
    import rule_engine
    rs = rule_engine.current()
    an = _analyzer()
    deadline = deadline or (time.monotonic() + MAX_SECONDS)
    install_setups = rule_engine.install_time_setups(rs, files)
    items, limits, seen = [], [], set()
    counts: dict[str, int] = {}
    analyzed = 0
    for path in files:
        if analyzed >= MAX_FILES:
            limits.append(f"analyzed only the first {MAX_FILES} files")
            break
        if time.monotonic() > deadline:
            limits.append("ran out of time before analyzing every file")
            break
        try:
            if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        lang = "python" if path.suffix in (".py", ".pth") else rule_engine.lang_of(rs, path)
        if lang != "python":
            if lang not in patterns():
                continue
            phase = _other_phase(rs, rule_engine, lang, path, install_files)
            if phase is None:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            found, _ev, file_limits = _pattern_file(rs, rule_engine, lang, path, text, phase), [], []
            rel = rule_engine.package_relative(path)
            analyzed += 1
            module_calls = set()
        else:
            phase = _phase(rs, rule_engine, path, install_setups)
            if phase is None:
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            source = _pth_source(text) if path.suffix == ".pth" else text
            rel = rule_engine.package_relative(path)
            try:
                found, _ev, file_limits = an.analyze_file(rel, source, hashlib.sha256(text.encode()).hexdigest(), "", phase, [])
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                continue
            analyzed += 1
            module_calls = _called_at_module_level(source) if phase == "import" and any(c.get("symbol") for c in found) else set()
        if "dynamic code not analyzed" in file_limits:
            found = list(found) + [{"kind": "dynamic_code", "target": None, "symbol": None,
                                    "path_categories": [], "confidence": "medium", "_line": None}]
        for c in found:
            if not _keep(c):
                continue
            when = c.get("when") or ("call" if c.get("symbol") and phase == "import" and c["symbol"] not in module_calls else phase)
            line = c.get("_line")
            if line is None:
                ev = next((e for e in _ev if e["evidence_id"] in c.get("evidence_ids", [])), None)
                line = ev["location"]["line"] if ev else None
            key = (c["kind"], c.get("target"), when, rel)
            if key in seen:
                continue
            seen.add(key)
            counts[c["kind"]] = counts.get(c["kind"], 0) + 1
            items.append({"kind": c["kind"], "target": c.get("target"), "when": when,
                          "at": f"{rel}:{line}" if line else rel, "categories": c.get("path_categories") or [],
                          "confidence": c.get("confidence", "high")})
    # what runs code or talks to the network, then sensitive files, survives the cut; then earliest phase first
    items.sort(key=lambda c: (min(KIND_ORDER.get(c["kind"], 9), 3) if not c["categories"] else 2,
                              PHASE_ORDER.get(c["when"], 9), KIND_ORDER.get(c["kind"], 9), c["at"]))
    if len(items) > MAX_KEPT:
        limits.append(f"recorded only {MAX_KEPT} of {len(items)} capabilities")
    return {"items": items[:MAX_KEPT], "counts": counts, "files": analyzed, "limits": limits}
