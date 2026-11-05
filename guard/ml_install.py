"""
AegisPilot - installs the ML model (guard/ml) for this user: on the first PyPI check (auto_install), or ahead of time
with `guard_cli.py ml-install`.

  ~/.aegis/ml/models: the two model files of ml/models.json (JSON, read by the standard library only), downloaded from
  the GitHub release named there, or copied from a folder (--from DIR, e.g. offline). A file whose SHA-256 differs from
  models.json is refused. Nothing else is installed: no environment, no pip.

The guard checks the hashes again before every run (ml_bridge.py, and ml/forest.py before it parses a file):
~/.aegis/ml can be written by anything that runs as this user. A person runs this from a terminal; the agent running
it is asked about first (guard_paths: a change to the guard's install).
The ~/.aegis/ml/venv folder of version 1 (scikit-learn) is no longer used; it is left in place and can be deleted.

Automatic download: when the model files are missing, the first PyPI check downloads them (auto_install). It is the
same download and the same hash check as ml-install, with a 30-second limit; a failure is remembered for 6 hours so
checks do not keep waiting on it, and the verdict is rule-based meanwhile. `ml-uninstall` leaves a marker (<folder>.off)
so the files are not downloaded again; `ml-install` removes it. AEGIS_ML=0 turns ML off without downloading anything.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import time
import urllib.request
from pathlib import Path

ML_CODE = Path(__file__).resolve().parent / "ml"
MAX_MODEL_BYTES = 64 * 1024 * 1024
AUTO_TIMEOUT = 30                    # seconds per file for the automatic download (ml-install waits longer)
AUTO_RETRY_SECONDS = 6 * 3600        # after a failed automatic download, rules only for this long
LOCK_STALE_SECONDS = 300


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


def _fetch(url: str, dest: Path, timeout: int = 120) -> None:
    if not url.startswith("https://"):
        raise ValueError(f"not an https address: {url}")
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        raw = resp.read(MAX_MODEL_BYTES + 1)
    if len(raw) > MAX_MODEL_BYTES:
        raise ValueError(f"{url}: larger than {MAX_MODEL_BYTES >> 20}MB")
    dest.write_bytes(raw)


def install_models(target: Path, source: Path | None = None, log=print, timeout: int = 120) -> None:
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
                _fetch(s["release_url"] + m["file"], part, timeout)
            if _sha256(part) != m["sha256"]:
                raise ValueError(f"{m['file']}: SHA-256 differs from models.json, not installed")
        for m in s["models"].values():
            os.replace(Path(tmp) / m["file"], target / m["file"])


def opt_out_marker(folder: Path) -> Path:
    folder = Path(folder)
    return folder.with_name(folder.name + ".off")


def opted_out(folder: Path) -> bool:
    """The person removed the model with ml-uninstall: do not download it again by itself."""
    return opt_out_marker(folder).exists()


def _auto_state(folder: Path) -> Path:
    return Path(folder) / ".auto_failed"


def last_auto_failure(folder: Path) -> tuple[float, str] | None:
    try:
        d = json.loads(_auto_state(folder).read_text())
        return float(d["at"]), str(d.get("error", ""))
    except (OSError, ValueError, KeyError, TypeError):
        return None


def auto_install(folder: Path, now: float | None = None) -> str | None:
    """Download the model files on first use. None when they are in place afterwards; otherwise why not (the check then
    goes on with rules only). Never raises."""
    folder = Path(folder)
    now = time.time() if now is None else now
    try:
        if opted_out(folder):
            return "turned off with ml-uninstall (ml-install turns it back on)"
        failed = last_auto_failure(folder)
        if failed and now - failed[0] < AUTO_RETRY_SECONDS:
            return f"the last automatic download failed ({failed[1]}); it is tried again later, or run guard_cli.py ml-install"
        folder.mkdir(parents=True, exist_ok=True)
        lock = folder / ".auto.lock"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                stale = now - lock.stat().st_mtime > LOCK_STALE_SECONDS
            except OSError:
                stale = False
            if not stale:
                return "another check is downloading the model files"
            lock.unlink(missing_ok=True)
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        try:
            install_models(folder / "models", None, log=lambda *_: None, timeout=AUTO_TIMEOUT)
            _auto_state(folder).unlink(missing_ok=True)
            return None
        except Exception as e:
            why = f"{type(e).__name__}: {e}"[:200]
            try:
                _auto_state(folder).write_text(json.dumps({"at": now, "error": why}))
            except OSError:
                pass
            return f"automatic download failed ({why})"
        finally:
            lock.unlink(missing_ok=True)
    except Exception as e:
        return f"automatic download not possible ({type(e).__name__}: {e})"[:240]


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
    if problem and opted_out(folder):
        return "turned off with ml-uninstall (rules only). To turn it back on: guard_cli.py ml-install" + tail
    try:
        none_there = not any((folder / "models" / m["file"]).exists() for m in spec()["models"].values())
    except (OSError, ValueError, KeyError):
        none_there = not (folder / "models").is_dir()
    failed = last_auto_failure(folder)
    if problem and none_there and failed:
        return f"not installed: the last automatic download failed ({failed[1]}). To retry now: guard_cli.py ml-install" + tail
    if problem and none_there:
        return "not installed yet: downloaded automatically on the first PyPI check (about 9MB; AEGIS_ML=0 turns ML off)" + tail
    if problem:
        return f"not used: {problem} (run guard_cli.py ml-install)" + tail
    return f"installed in {folder}" + tail
