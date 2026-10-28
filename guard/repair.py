"""
AegisPilot - put an installed guard back to its official build.

When the integrity check finds the guard's files changed, nobody can tell from inside the guard who changed them. The
repair restores the official files and keeps what it replaced:

  1. a source: another build of the guard (`--from DIR`, whose own files must match its own checksums), or the
     official repository at the commit this build was made from (BUILD_INFO.json "source"), built into a temporary
     folder with that commit's scripts/build_dist.py. A plugin build (BUILD_INFO "layout": "plugin") is the
     public repository itself: its release tag (BUILD_INFO "ref") is fetched and used as it is
  2. every file that differs from the source, and every file the source does not have (.py .pth .json .pyc), is copied
     to ~/.aasm/quarantine/<time>/ before anything is changed
  3. the source's files are copied over, extra files removed, and the result is checked again

What is "official" is never decided by whoever runs it: the source is the official commit (or --from), checked
against its own checksums. So a person at a terminal (typed confirmation) and an agent in auto mode (--yes, from the
integrity card) run the same restore. Nothing here runs code from the installed guard's own files except
this module; the source build runs code from the official commit.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GUARD_DIR = Path(__file__).resolve().parent
_EXTRA_KINDS = (".py", ".pth", ".json", ".pyc")
_KEEP = {"BUILD_INFO.json", "RELEASE_MANIFEST.json"}      # replaced from the source as a whole


class RepairError(Exception):
    pass


def _sha(p: Path) -> str | None:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


def manifest_of(root: Path) -> dict[str, str]:
    try:
        files = json.loads((root / "RELEASE_MANIFEST.json").read_text())["files"]
        if isinstance(files, dict) and files:
            return files
    except (OSError, ValueError, KeyError, TypeError):
        pass
    raise RepairError(f"no checksum list (RELEASE_MANIFEST.json) in {root} - not a built guard folder")


def check_source(src: Path) -> dict[str, str]:
    """The source build's own files must match its own manifest (a damaged source is not a repair)."""
    files = manifest_of(src)
    bad = [rel for rel, sha in files.items() if _sha(src / rel) != sha]
    if bad:
        raise RepairError(f"{len(bad)} file(s) in restore source {src} differ from its own checksums (e.g. {bad[0]}) - cannot use it")
    return files


def build_from_repo(url: str, commit: str, dest: Path) -> Path:
    """The official repository at `commit`, built with its own scripts/build_dist.py into dest/build."""
    from sources import repo
    root = repo.fetch(url, commit, dest / "src")
    out = dest / "build"
    r = subprocess.run([sys.executable, str(root / "scripts" / "build_dist.py"), "test", "--out", str(out), "--skip-tests"],
                       cwd=root, capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not (out / "RELEASE_MANIFEST.json").exists():
        raise RepairError(f"could not build the official repository ({url}@{commit[:12]}): {(r.stdout + r.stderr)[-200:]}")
    return out


def plan(target: Path, src_files: dict[str, str]) -> dict:
    """What a repair would do: {"replace": [rel], "remove": [rel], "add": [rel]} (nothing is changed)."""
    replace, add = [], []
    for rel, sha in src_files.items():
        if rel in _KEEP:
            continue                                     # build records: copied from the source as a pair
        cur = _sha(target / rel)
        if cur is None:
            add.append(rel)
        elif cur != sha:
            replace.append(rel)
    remove = []
    for f in sorted(target.rglob("*")):
        rel = str(f.relative_to(target))
        if f.is_file() and rel not in src_files and rel not in _KEEP and f.suffix.lower() in _EXTRA_KINDS \
                and not ("__pycache__" in f.parts and f.suffix == ".pyc"):
            remove.append(rel)
    return {"replace": replace, "remove": remove, "add": add}


def apply(target: Path, src: Path, todo: dict, quarantine_root: Path) -> Path:
    """Quarantine what changes, then copy the source over. Returns the quarantine folder."""
    q = quarantine_root / time.strftime("%Y%m%d-%H%M%S")
    q.mkdir(parents=True, exist_ok=False)
    for rel in todo["replace"] + todo["remove"] + [k for k in _KEEP if (target / k).exists()]:
        dst = q / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target / rel, dst)
    for rel in todo["remove"]:
        (target / rel).unlink()
    for rel in todo["replace"] + todo["add"] + [k for k in _KEEP if (src / k).exists()]:
        (target / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, target / rel)
    for cache in target.rglob("__pycache__"):            # compiled copies of replaced files: rebuilt from source
        shutil.rmtree(cache, ignore_errors=True)
    (q / "REPAIR.json").write_text(json.dumps({"target": str(target), "source": str(src), **todo,
                                               "at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}, ensure_ascii=False, indent=1))
    return q


def source_info(target: Path) -> tuple[str | None, str | None]:
    """(repository URL, commit) recorded at build time."""
    info = _build_info(target)
    return info.get("source"), info.get("commit")


def _build_info(target: Path) -> dict:
    try:
        info = json.loads((target / "BUILD_INFO.json").read_text())
        return info if isinstance(info, dict) else {}
    except (OSError, ValueError):
        return {}


def fetch_release(url: str, ref: str, dest: Path) -> Path:
    """A published plugin: the public repository at its release tag, every file kept (the plugin is a folder in it)."""
    from sources import repo
    try:
        return repo.fetch(url, ref, dest / "src", keep=repo.ALL_FILES)
    except Exception as e:
        raise RepairError(f"could not fetch the official repository ({url}@{ref}): {type(e).__name__}: {e}"[:300]) from None


def prepare(target: Path, from_dir: Path | None, workdir: Path) -> tuple[Path, dict[str, str], str]:
    """(source build, its files, a description of where it came from)."""
    if from_dir is not None:
        return from_dir, check_source(from_dir), str(from_dir)
    info = _build_info(target)
    if info.get("layout") == "plugin":
        if not info.get("source") or not info.get("ref"):
            raise RepairError("official source of this plugin unknown (source/ref in BUILD_INFO.json) - name a source with --from <built guard folder>")
        src = fetch_release(info["source"], info["ref"], workdir)
        if info.get("path"):       # the plugin is one folder of the repository (guard/)
            src = src / info["path"]
            if not src.is_dir():
                raise RepairError(f"no plugin folder {info['path']}/ in the official repository ({info['source']}@{info['ref']})")
        return src, check_source(src), f"{info['source']}@{info['ref']}/{info.get('path', '')}".rstrip("/")
    url, commit = source_info(target)
    if not url or not commit:
        raise RepairError("official source of this guard unknown (source/commit in BUILD_INFO.json) - name a source with --from <built guard folder>")
    src = build_from_repo(url, commit, workdir)
    return src, check_source(src), f"{url}@{commit[:12]}"
