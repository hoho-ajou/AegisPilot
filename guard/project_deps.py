"""
AegisPilot - what a project-level install pulls in: the project's direct dependencies, pinned from its lock file.

`pip install .`, `uv sync`, `poetry install`, `pipenv sync`, `pip-sync` ... name no package on the command line; the
packages come from the project's files. Without this, with pyyaml==5.3.1 in pyproject.toml / Pipfile / a lock file,
10 of 12 such commands installed it with no word from the guard.

Read, never executed:
  manifests  pyproject.toml ([project] dependencies + optional-dependencies, [dependency-groups],
             [tool.poetry.*dependencies] + groups, [tool.pdm.dev-dependencies]), Pipfile, setup.cfg install_requires
  locks      uv.lock, poetry.lock, pdm.lock, Pipfile.lock -> the exact version a direct dependency resolves to
  wheels     a local .whl's METADATA Requires-Dist

Scope: direct dependencies only, with the lock's version when there is one. Transitive dependencies
are not scanned (hundreds of packages would not fit the scan budget) and the record says so. Sync commands are treated
as installing every group and extra (a superset: at worst an extra REVIEW, never a silent pass).
What cannot be known without running code (setup.py, `dynamic = ["dependencies"]`, an sdist archive) is returned as
"unreadable" so the guard asks instead of passing.
"""
from __future__ import annotations

import configparser
import json
import re
import tomllib
import zipfile
from pathlib import Path

MAX_FILE_BYTES = 2 * 1024 * 1024


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _read(path: Path):
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("file too large")
    return path.read_text(errors="replace")


def _poetry_spec(name: str, value) -> str | None:
    """poetry `pyyaml = "5.3.1"` / `{version = "^5.3"}` -> a PEP 508 string (exact only when the value is a plain version)."""
    if isinstance(value, dict):
        if any(k in value for k in ("git", "url", "path")):
            return f"{name} @ {value.get('git') or value.get('url') or value.get('path')}"
        value = value.get("version", "*")
    if isinstance(value, list):
        value = (value[0] or {}).get("version", "*") if value and isinstance(value[0], dict) else "*"
    v = str(value).strip()
    if re.fullmatch(r"\d[\w.!+-]*", v):
        return f"{name}=={v}"                 # poetry: a bare version is an exact pin
    if v.startswith("=="):
        return f"{name}{v}"
    return name                               # ^, ~, >=, * : a range -> version comes from the lock or the latest


def _pipfile_spec(name: str, value) -> str:
    if isinstance(value, dict):
        if any(k in value for k in ("git", "file", "path")):
            return f"{name} @ {value.get('git') or value.get('file') or value.get('path')}"
        value = value.get("version", "*")
    v = str(value).strip()
    return f"{name}{v}" if v.startswith("==") else name


def manifest(project: Path, extras: set[str] | None = None, all_groups: bool = False) -> tuple[list[str], list[str]]:
    """(requirement strings, unreadable reasons) for the project in `project`.
    extras: the extras asked for (`.[dev]`); all_groups: sync-style commands that install every group."""
    reqs, unreadable = [], []
    try:
        text = _read(project / "pyproject.toml")
        if text is not None:
            doc = tomllib.loads(text)
            proj = doc.get("project") or {}
            if "dependencies" in (proj.get("dynamic") or []):
                unreadable.append("pyproject.toml: dependencies are dynamic (computed at build time), cannot be known without running code")
            reqs += [str(r) for r in proj.get("dependencies") or []]
            for extra, items in (proj.get("optional-dependencies") or {}).items():
                if all_groups or (extras and (extra in extras or "all" in extras)):
                    reqs += [str(r) for r in items]
            for group, items in (doc.get("dependency-groups") or {}).items():
                if all_groups or group == "dev":          # uv installs the dev group by default
                    reqs += [str(r) for r in items if isinstance(r, str)]
            poetry = (doc.get("tool") or {}).get("poetry") or {}
            tables = [poetry.get("dependencies") or {}, poetry.get("dev-dependencies") or {}]
            tables += [(g or {}).get("dependencies") or {} for g in (poetry.get("group") or {}).values()]
            for table in tables:
                for name, value in table.items():
                    if name.lower() != "python":
                        spec = _poetry_spec(name, value)
                        if spec:
                            reqs.append(spec)
            for items in (((doc.get("tool") or {}).get("pdm") or {}).get("dev-dependencies") or {}).values():
                reqs += [str(r) for r in items if isinstance(r, str)]
    except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
        unreadable.append(f"could not read pyproject.toml ({type(e).__name__})")
    try:
        text = _read(project / "Pipfile")
        if text is not None:
            doc = tomllib.loads(text)
            for table in ("packages", "dev-packages"):
                reqs += [_pipfile_spec(n, v) for n, v in (doc.get(table) or {}).items()]
    except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
        unreadable.append(f"could not read Pipfile ({type(e).__name__})")
    try:
        text = _read(project / "setup.cfg")
        if text is not None:
            cfg = configparser.ConfigParser()
            cfg.read_string(text)
            if cfg.has_option("options", "install_requires"):
                reqs += [r.strip() for r in cfg.get("options", "install_requires").splitlines() if r.strip()]
    except (OSError, ValueError, configparser.Error) as e:
        unreadable.append(f"could not read setup.cfg ({type(e).__name__})")
    if (project / "setup.py").is_file() and not reqs and not unreadable:
        unreadable.append("setup.py: dependencies are declared in code, cannot be known without running it")
    return reqs, unreadable


def lock_pins(project: Path) -> tuple[dict[str, str], list[str]]:
    """normalized name -> exact version from whichever lock files exist."""
    pins, unreadable = {}, []
    for fname in ("uv.lock", "poetry.lock", "pdm.lock"):
        try:
            text = _read(project / fname)
            if text is None:
                continue
            for pkg in tomllib.loads(text).get("package") or []:
                if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                    pins.setdefault(_norm(pkg["name"]), str(pkg["version"]))
        except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
            unreadable.append(f"could not read {fname} ({type(e).__name__})")
    try:
        text = _read(project / "Pipfile.lock")
        if text is not None:
            doc = json.loads(text)
            for section in ("default", "develop"):
                for name, info in (doc.get(section) or {}).items():
                    v = str((info or {}).get("version", ""))
                    if v.startswith("=="):
                        pins.setdefault(_norm(name), v[2:])
    except (OSError, ValueError) as e:
        unreadable.append(f"could not read Pipfile.lock ({type(e).__name__})")
    return pins, unreadable


def pipfile_lock_direct(project: Path) -> list[str]:
    """`pipenv sync` with only Pipfile.lock: the lock lists everything; without the Pipfile the direct ones are unknown,
    so every locked package is returned (the 200-package cap reports the rest)."""
    try:
        doc = json.loads(_read(project / "Pipfile.lock") or "{}")
    except (OSError, ValueError):
        return []
    return [f"{n}{(i or {}).get('version', '')}" for s in ("default", "develop") for n, i in (doc.get(s) or {}).items()]


def wheel_requires(path: Path) -> tuple[list[str], list[str]]:
    """Requires-Dist of a local wheel (extras-only requirements skipped)."""
    try:
        with zipfile.ZipFile(path) as z:
            meta = next((n for n in z.namelist() if n.endswith(".dist-info/METADATA")), None)
            if meta is None:
                return [], [f"{path.name}: no METADATA"]
            text = z.read(meta).decode(errors="replace")
    except (OSError, zipfile.BadZipFile) as e:
        return [], [f"could not read {path.name} ({type(e).__name__})"]
    reqs = []
    for line in text.splitlines():
        if line.startswith("Requires-Dist:"):
            req = line.split(":", 1)[1].strip()
            if "extra ==" not in req.split(";", 1)[-1]:
                reqs.append(req.split(";", 1)[0].strip())
    return reqs, []
