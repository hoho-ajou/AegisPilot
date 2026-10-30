"""
AegisPilot - writes into folders the agent can also write (<project>/.aegis, ~/.aegis).

The agent could plant a symbolic link there (`ln -s ~/.bashrc .aegis/attack_paths.json`, or `.aegis` itself pointing
elsewhere), and a plain write would follow it: the hook runs outside the agent's sandbox, before the person answers, and
would overwrite the link's target. So every folder from the base folder down must be a real folder (not a link), and a
file is written to a new temporary file in that folder and then renamed over the name, which replaces a link instead
of following it.
"""
from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


def real_dir(base: Path, sub: Path | None = None) -> Path:
    """Create (if needed) base and the folders of sub below it, refusing any part that is a link or not a folder.
    Raises OSError."""
    base = Path(base)
    parts = [base] + ([base / p for p in _accumulate(Path(sub).parts)] if sub else [])
    for d in parts:
        try:
            st = os.lstat(d)
        except FileNotFoundError:
            try:
                os.mkdir(d)
            except FileExistsError:                     # made by a parallel hook in the meantime
                pass
            st = os.lstat(d)
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise OSError(f"not a real folder: {d}")
    return parts[-1]


def _accumulate(parts: tuple) -> list[Path]:
    out, cur = [], Path()
    for p in parts:
        if p in ("", ".", "..") or os.sep in p:
            raise OSError(f"bad folder name: {p!r}")
        cur = cur / p
        out.append(cur)
    return out


def write_text(base: Path, rel: str | Path, text: str) -> Path:
    """Write base/rel atomically without following links (see the module text). Raises OSError."""
    rel = Path(rel)
    folder = real_dir(base, rel.parent if rel.parent != Path(".") else None)
    target = folder / rel.name
    fd, tmp = tempfile.mkstemp(prefix="." + rel.name + ".", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return target


def create_once(base: Path, rel: str, text: str) -> None:
    """Create base/rel when nothing (not even a dangling link) has that name; leave anything already there alone."""
    folder = real_dir(base)
    try:
        fd = os.open(folder / rel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        return
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
