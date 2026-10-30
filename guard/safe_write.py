"""
AegisPilot - writes into folders the agent can also write (<project>/.aegis, ~/.aegis).

The agent could plant a symbolic link there (`ln -s ~/.bashrc .aegis/attack_paths.json`, or `.aegis` itself pointing
elsewhere), and a plain write would follow it: the hook runs outside the agent's sandbox, before the person answers, and
would overwrite the link's target. So every folder from the base folder down must be a real folder (not a link), and a
file is written to a new temporary file in that folder and then renamed over the name, which replaces a link instead
of following it.

Where the system allows it (Linux, macOS), the folders are opened one by one without following links and every later
step works relative to the opened folder, so a folder swapped for a link between the check and the write cannot
redirect it. Elsewhere the same checks run on paths.
"""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

_FDS = hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd


def _parts(sub) -> list[str]:
    out = []
    for p in Path(sub).parts if sub else ():
        if p in ("", ".", "..") or os.sep in p:
            raise OSError(f"bad folder name: {p!r}")
        out.append(p)
    return out


def _check(st: os.stat_result, where) -> None:
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OSError(f"not a real folder: {where}")


def _open_dir(base: Path, sub=None) -> int:
    """A file descriptor of base/sub, made as needed, never through a link. Raises OSError."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    base = Path(base)
    try:
        os.mkdir(base)
    except FileExistsError:
        pass
    _check(os.lstat(base), base)
    fd = os.open(base, flags)
    try:
        for name in _parts(sub):
            try:
                os.mkdir(name, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(name, flags, dir_fd=fd)       # O_NOFOLLOW: a link here fails instead of being followed
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd


def real_dir(base: Path, sub: Path | None = None) -> Path:
    """Create (if needed) base and the folders of sub below it, refusing any part that is a link or not a folder.
    Raises OSError."""
    if _FDS:
        os.close(_open_dir(base, sub))
        return Path(base).joinpath(*_parts(sub))
    parts = [Path(base)]
    for name in _parts(sub):
        parts.append(parts[-1] / name)
    for d in parts:
        try:
            os.mkdir(d)
        except FileExistsError:                         # there already, or made by a parallel hook in the meantime
            pass
        _check(os.lstat(d), d)
    return parts[-1]


def write_text(base: Path, rel: str | Path, text: str) -> Path:
    """Write base/rel atomically without following links (see the module text). Raises OSError."""
    rel = Path(rel)
    sub = rel.parent if rel.parent != Path(".") else None
    name = rel.name
    if not name or name in (".", ".."):
        raise OSError(f"bad file name: {rel}")
    data = text.encode("utf-8")
    tmp = f".{name}.{secrets.token_hex(6)}.tmp"
    if not _FDS:
        folder = real_dir(base, sub)
        fd = os.open(folder / tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(folder / tmp, folder / name)
        except BaseException:
            _unlink(folder / tmp)
            raise
        return folder / name
    dfd = _open_dir(base, sub)
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except BaseException:
            _unlink(tmp, dfd)
            raise
    finally:
        os.close(dfd)
    return Path(base).joinpath(*_parts(sub), name)


def create_once(base: Path, rel: str, text: str) -> None:
    """Create base/rel when nothing (not even a dangling link) has that name; leave anything already there alone."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    if _FDS:
        dfd = _open_dir(base)
        try:
            fd = os.open(rel, flags, 0o644, dir_fd=dfd)
        except FileExistsError:
            return
        finally:
            os.close(dfd)
    else:
        try:
            fd = os.open(real_dir(base) / rel, flags, 0o644)
        except FileExistsError:
            return
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _unlink(path, dir_fd=None) -> None:
    try:
        os.unlink(path, dir_fd=dir_fd)
    except OSError:
        pass
