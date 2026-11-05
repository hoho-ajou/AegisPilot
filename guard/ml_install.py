"""
AegisPilot - installs the optional ML model (guard/ml) for this user: `guard_cli.py ml-install`.

  ~/.aegis/ml/models: the two model files of ml/models.json (JSON, read by the standard library only), downloaded from
  the GitHub release named there, or copied from a folder (--from DIR, e.g. offline). A file whose SHA-256 differs from
  models.json is refused. Nothing else is installed: no environment, no pip.

The guard checks the hashes again before every run (ml_bridge.py, and ml/forest.py before it parses a file):
~/.aegis/ml can be written by anything that runs as this user. A person runs this from a terminal; the agent running
it is asked about first (guard_paths: a change to the guard's install).
The ~/.aegis/ml/venv folder of version 1 (scikit-learn) is no longer used; it is left in place and can be deleted.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.request
from pathlib import Path

ML_CODE = Path(__file__).resolve().parent / "ml"
MAX_MODEL_BYTES = 64 * 1024 * 1024


def spec() -> dict:
    return json.loads((ML_CODE / "models.json").read_text())


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_models(folder: Path) -> str | None:
    """None when every model file in models.json is in `folder` with its SHA-256; otherwise what is wrong."""
    try:
        models = spec()["models"]
    except (OSError, ValueError, KeyError) as e:
        return f"models.json unreadable ({type(e).__name__})"
    for m in models.values():
        f = Path(folder) / m["file"]
        if f.is_symlink() or not f.is_file():
            return f"{m['file']} missing"
        if _sha256(f) != m["sha256"]:
            return f"{m['file']} differs from models.json (SHA-256)"
    return None


def _fetch(url: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise ValueError(f"not an https address: {url}")
    with urllib.request.urlopen(url, timeout=120) as resp:
        raw = resp.read(MAX_MODEL_BYTES + 1)
    if len(raw) > MAX_MODEL_BYTES:
        raise ValueError(f"{url}: larger than {MAX_MODEL_BYTES >> 20}MB")
    dest.write_bytes(raw)


def install_models(target: Path, source: Path | None = None, log=print) -> None:
    """Put the model files into target/: from `source` or the release URL, each checked before it is moved in."""
    s = spec()
    target.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=target.parent) as tmp:
        for m in s["models"].values():
            part = Path(tmp) / m["file"]
            if source:
                src = Path(source) / m["file"]
                if src.is_symlink() or not src.is_file():
                    raise ValueError(f"{src} missing")
                shutil.copyfile(src, part)
            else:
                log(f"  downloading {m['file']} ({m['size'] / 1e6:.1f}MB)")
                _fetch(s["release_url"] + m["file"], part)
            if _sha256(part) != m["sha256"]:
                raise ValueError(f"{m['file']}: SHA-256 differs from models.json, not installed")
        for m in s["models"].values():
            os.replace(Path(tmp) / m["file"], target / m["file"])


def legacy_venv(folder: Path) -> Path | None:
    """The environment of ML version 1, if it is still there (no longer used)."""
    v = Path(folder) / "venv"
    return v if v.is_dir() else None


def uninstall(folder: Path) -> bool:
    """Delete the ML folder. A link anywhere on the way (~/.aegis planted as a link to ~) would make this delete
    another folder than the one named, so a linked folder is unlinked, never followed."""
    folder = Path(os.path.abspath(folder))
    for parent in reversed(folder.parents):
        if parent.is_symlink():
            raise ValueError(f"{parent} is a link: remove {folder} yourself")
    if folder.is_symlink():
        folder.unlink()
        return True
    if folder.is_dir():
        shutil.rmtree(folder)
        return True
    return False


def status(folder: Path) -> str:
    folder = Path(folder)
    problem = check_models(folder / "models")
    old = legacy_venv(folder)
    tail = f" ({old} is from ML version 1 and no longer used: it can be deleted)" if old else ""
    if problem and not (folder / "models").exists():
        return "not installed (rules only). To add it: guard_cli.py ml-install" + tail
    if problem:
        return f"not used: {problem} (run guard_cli.py ml-install)" + tail
    return f"installed in {folder}" + tail
