"""
AegisPilot - safe extraction of an untrusted package archive.

The guard unpacks attacker-controlled archives BEFORE the user has decided anything, so unpacking itself must not be
an attack surface. Measured on the previous `extractall`: a 0.3MB archive wrote 315MB to disk,
symlink/hardlink members wrote outside the extraction dir, one odd member name aborted the whole analysis.

What this does instead:
  - extracts ONLY what the analysis reads: `.py`, `.pth` and an empty marker file for a README (reputation signal)
  - never creates links, devices, directories from members; every target is re-checked to stay under the root
  - a member with an unsafe name (absolute, `..`, drive letter, NUL, over-long) is SKIPPED and reported, not fatal
    - skipped names are a finding: hiding a file behind a strange name is itself suspicious (REVIEW)
  - limits, all of which end in ArchiveLimitError -> the package is reported as "not analyzed" (REVIEW):
      member count, one member's size, total size of what we extract, and the COMPRESSION RATIO
  - never recurses into nested archives (a nested archive is just a file, so layered bombs stay inert)

Limit values come from measurements: real wheels/sdists never exceeded 47x per member
or 24x per whole stream; the largest `.py`/`.pth` total was 216MB and the largest single file 16.6MB; a bomb is ~1000x.
"""
from __future__ import annotations

import io
import os
import re
import tarfile
import zipfile
import zlib
from pathlib import Path

WANTED_SUFFIXES = (".py", ".pth")
MAX_RATIO = 150                       # inflated / compressed; real max 47 (wheel member) and 24 (sdist stream)
RATIO_MIN_BYTES = 1024 * 1024         # a tiny file can compress extremely well without being a threat
MAX_MEMBER_BYTES = 64 * 1024 * 1024   # real max 16.6MB
MAX_TOTAL_BYTES = 512 * 1024 * 1024   # of what we extract; real max 216MB
MAX_MEMBERS = 100_000                 # real max 24,013
MAX_STREAM_INFLATED = 2 * 1024 * 1024 * 1024   # tar.gz: everything the gzip stream inflates to, wanted or not
MAX_NAME_COMPONENT = 255
MAX_NAME_TOTAL = 1024
_CHUNK = 1024 * 1024
_DRIVE = re.compile(r"^[A-Za-z]:")


class ArchiveLimitError(Exception):
    """A limit was exceeded: the archive is not analyzed and the package is reported for human review."""


def clean_member_name(name: str) -> tuple[Path | None, str | None]:
    """(relative path, None) for a safe name, else (None, reason). Backslash counts as a separator on purpose:
    conservative for names written for Windows."""
    if "\x00" in name:
        return None, "NUL in name"
    if name.startswith(("/", "\\")) or _DRIVE.match(name):
        return None, "absolute path"
    parts = [p for p in re.split(r"[\\/]", name) if p not in ("", ".")]
    if not parts:
        return None, "empty name"
    if ".." in parts:
        return None, "path traversal (..)"
    if len(name.encode("utf-8", "ignore")) > MAX_NAME_TOTAL or any(len(p.encode("utf-8", "ignore")) > MAX_NAME_COMPONENT for p in parts):
        return None, "over-long name"
    return Path(*parts), None


def _target(root: Path, rel: Path) -> Path | None:
    """root/rel when it stays inside root after resolving, else None. Defence in depth: we create no links, but the
    directory may contain something unexpected."""
    target = root / rel
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        base = os.path.realpath(root)
        if os.path.commonpath([base, os.path.realpath(target.parent)]) != base:
            return None
    except (OSError, ValueError):
        return None
    return target


def _is_readme(name: str) -> bool:
    base = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base == "readme" or base.startswith("readme.")


def _wanted(name: str, suffixes: tuple = WANTED_SUFFIXES) -> bool:
    return name.lower().endswith(suffixes)


# What a PyPI scan extracts besides .py/.pth (measured on real packages): by what a file can DO
# once installed, not by a list of paths an attacker could move away from.
#  - text an agent reads (agent-directed instructions): .js .ts .md .rst .txt. Data files (.json/.yaml) are left out: in
#    the measurement every hit there was a dataset of attack phrases in a security / LLM tool (garak, pyrit, litellm)
#  - files a wheel installs OUTSIDE its package (<dist>.data/scripts -> bin, <dist>.data/data -> the environment root):
#    any type - a command in bin or a file in the environment root can run without being imported
#  - entry_points.txt: the command names the package installs
#  - .pyc: only its presence (a module shipped without source cannot be read)
TEXT_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".md", ".rst", ".txt")
TEXT_MAX_BYTES = 1024 * 1024          # minified UI bundles run to 10-40MB per package; the attacks seen were small files
PLACED_MAX_BYTES = 1024 * 1024
MARKER_SUFFIXES = (".pyc",)
_PLACED = re.compile(r"^[^/]+\.data/(scripts|data)/")


def member_policy(name: str, size: int, suffixes: tuple = WANTED_SUFFIXES) -> str | None:
    """"extract", "marker" (an empty file: the name matters, not the content) or None (left in the archive).
    A caller that passes its own suffixes (npm, git sources) gets exactly those plus the README marker."""
    low = name.replace("\\", "/").lower()
    if low.endswith(suffixes):
        return "extract"
    if suffixes is WANTED_SUFFIXES:
        if _PLACED.match(low):
            return "extract" if size <= PLACED_MAX_BYTES else "marker"
        if low.endswith(".dist-info/entry_points.txt") or (low.endswith(TEXT_SUFFIXES) and size <= TEXT_MAX_BYTES):
            return "extract"
        if low.endswith(MARKER_SUFFIXES):
            return "marker"
    return "marker" if _is_readme(name) else None


# Files an sdist build can run without importing them - the Makefile or configure script `make` / `sh` runs, a data file
# setup.py exec()s, the pyproject.toml naming an in-tree build backend - are not code the rules read. A caller that
# passes `aside` gets them written there (`<archive>.aside/`, next to the root, so they stay out of the file list); the
# behavior analysis reads one only when install-time code hands work to it. Members too large for it are listed in
# `<archive>.aside.left`: a file the build runs but nobody read is a finding of its own.
ASIDE_MAX_BYTES = 1024 * 1024
ASIDE_TOTAL_BYTES = 64 * 1024 * 1024


def aside_dir(root: Path) -> Path:
    """Where extract_* puts the members it does not extract when asked to keep them aside (see ASIDE_MAX_BYTES)."""
    name = root.name[:-len(".unpacked")] if root.name.endswith(".unpacked") else root.name
    return root.with_name(name + ".aside")


class _Aside:
    def __init__(self, path: Path | None):
        self.path, self.total, self.left = path, 0, []

    def wants(self, rel: Path, size: int) -> bool:
        if self.path is None:
            return False
        if size > ASIDE_MAX_BYTES or self.total + size > ASIDE_TOTAL_BYTES:
            self.left.append(rel.as_posix())
            return False
        self.total += size
        return True

    def close(self) -> None:
        if self.path is not None and self.left:
            try:
                self.path.with_name(self.path.name + ".left").write_text("\n".join(self.left[:10000]) + "\n")
            except OSError:
                pass


def check_member(name: str, size: int, compressed: int | None) -> None:
    """Per-member limits (zip: both sizes are in the central directory)."""
    if size > MAX_MEMBER_BYTES:
        raise ArchiveLimitError(f"archive limit exceeded: {name[:80]} one file is {size / 1e6:.0f}MB (limit {MAX_MEMBER_BYTES >> 20}MB)")
    if compressed is not None and size >= RATIO_MIN_BYTES and size > MAX_RATIO * max(compressed, 1):
        raise ArchiveLimitError(f"archive limit exceeded: {name[:80]} compression ratio {size / max(compressed, 1):.0f}x (limit {MAX_RATIO}x) - possible zip bomb")


def extract_zip(raw: bytes, root: Path, skipped: list, suffixes: tuple = WANTED_SUFFIXES,
                aside: Path | None = None) -> list[Path]:
    """Extract the wanted members of a zip/wheel. skipped gets (name, reason) for unsafe members. suffixes: the file
    types kept (default Python; another ecosystem passes its own, e.g. npm keeps JavaScript and package.json).
    aside: where the other small members go (an sdist: see ASIDE_MAX_BYTES), None = left in the archive."""
    zf = zipfile.ZipFile(io.BytesIO(raw))
    infos = zf.infolist()
    if len(infos) > MAX_MEMBERS:
        raise ArchiveLimitError(f"archive limit exceeded: {len(infos)} files (limit {MAX_MEMBERS})")
    plan, declared = [], 0
    side = _Aside(aside)
    for i in infos:
        if i.is_dir():
            continue
        policy = member_policy(i.filename, i.file_size, suffixes)
        if policy is None and aside is None:
            continue
        rel, why = clean_member_name(i.filename)
        if rel is None:
            if policy is not None:
                skipped.append((i.filename[:120], why))
            continue
        if policy is None:
            if not (i.flag_bits & 0x1) and side.wants(rel, i.file_size):
                check_member(i.filename, i.file_size, i.compress_size)
                plan.append((i, rel, None))
            continue
        if policy == "marker":
            plan.append((i, rel, True)); continue
        if i.flag_bits & 0x1:
            skipped.append((i.filename[:120], "encrypted member")); continue
        check_member(i.filename, i.file_size, i.compress_size)
        declared += i.file_size
        if declared > MAX_TOTAL_BYTES:
            raise ArchiveLimitError(f"archive limit exceeded: extracted files total more than {MAX_TOTAL_BYTES >> 20}MB")
        plan.append((i, rel, False))
    out: list[Path] = []
    for i, rel, marker in plan:
        target = _target(root if marker is not None else aside, rel)
        if target is None:
            skipped.append((i.filename[:120], "resolves outside the extraction dir")); continue
        try:
            if marker:
                target.touch()
            else:
                left = i.file_size
                with zf.open(i) as src, open(target, "wb") as dst:
                    while True:
                        chunk = src.read(_CHUNK)
                        if not chunk:
                            break
                        left -= len(chunk)
                        if left < 0:
                            raise ArchiveLimitError(f"archive limit exceeded: {i.filename[:80]} inflates larger than declared")
                        dst.write(chunk)
            if marker is not None:
                out.append(target)
        except ArchiveLimitError:
            raise
        except (OSError, zipfile.BadZipFile, zlib.error, RuntimeError) as e:
            skipped.append((i.filename[:120], f"unreadable: {type(e).__name__}"))
    side.close()
    return out


class _BoundedGzip(io.RawIOBase):
    """Inflates a (possibly multi-member) gzip stream, counting output, and raises ArchiveLimitError as soon as the
    stream inflates beyond MAX_STREAM_INFLATED or its overall ratio passes MAX_RATIO."""

    def __init__(self, raw: bytes):
        self.raw, self.pos = raw, 0
        self.pending = b""
        self.d = zlib.decompressobj(31)
        self.out = b""
        self.inflated = 0

    def readable(self): return True

    def _fill(self) -> bool:
        while not self.out:
            if self.d.eof:
                self.pending = self.d.unused_data + self.pending
                if not self.pending and self.pos >= len(self.raw):
                    return False
                self.d = zlib.decompressobj(31)
            if not self.pending:
                if self.pos >= len(self.raw):
                    return False
                self.pending = self.raw[self.pos:self.pos + 65536]
                self.pos += len(self.pending)
            self.out = self.d.decompress(self.pending, _CHUNK)
            self.pending = self.d.unconsumed_tail
            self.inflated += len(self.out)
            if self.inflated > MAX_STREAM_INFLATED:
                raise ArchiveLimitError(f"archive limit exceeded: compressed stream inflates past {MAX_STREAM_INFLATED >> 30}GB")
            if self.inflated >= 64 * 1024 * 1024 and self.inflated > MAX_RATIO * max(self.pos - len(self.pending), 1):
                raise ArchiveLimitError(f"archive limit exceeded: compression ratio {self.inflated / max(self.pos, 1):.0f}x (limit {MAX_RATIO}x) - possible zip bomb")
        return True

    def readinto(self, b):
        if not self._fill():
            return 0
        n = min(len(b), len(self.out))
        b[:n], self.out = self.out[:n], self.out[n:]
        return n


def extract_targz(raw: bytes, root: Path, skipped: list, suffixes: tuple = WANTED_SUFFIXES,
                  aside: Path | None = None) -> list[Path]:
    """Extract the wanted members of a .tar.gz, streaming, with the stream limits of _BoundedGzip (suffixes, aside: see
    extract_zip)."""
    out: list[Path] = []
    total = count = 0
    side = _Aside(aside)
    try:
        tf = tarfile.open(fileobj=io.BufferedReader(_BoundedGzip(raw), _CHUNK), mode="r|")
        for m in tf:
            count += 1
            if count > MAX_MEMBERS:
                raise ArchiveLimitError(f"archive limit exceeded: more than {MAX_MEMBERS} files")
            if not m.isreg():
                continue                                   # dirs are created on demand; links/devices are never created
            policy = member_policy(m.name, m.size, suffixes)
            if policy is None and aside is None:
                continue
            rel, why = clean_member_name(m.name)
            if rel is None:
                if policy is not None:
                    skipped.append((m.name[:120], why))
                continue
            if policy is None:
                if side.wants(rel, m.size):
                    policy = "aside"
                else:
                    continue
            target = _target(aside if policy == "aside" else root, rel)
            if target is None:
                skipped.append((m.name[:120], "resolves outside the extraction dir")); continue
            try:
                if policy == "marker":
                    target.touch()
                else:
                    check_member(m.name, m.size, None)
                    total += m.size
                    if total > MAX_TOTAL_BYTES:
                        raise ArchiveLimitError(f"archive limit exceeded: extracted files total more than {MAX_TOTAL_BYTES >> 20}MB")
                    src = tf.extractfile(m)
                    with open(target, "wb") as dst:
                        while True:
                            chunk = src.read(_CHUNK)
                            if not chunk:
                                break
                            dst.write(chunk)
                if policy != "aside":
                    out.append(target)
            except OSError as e:
                skipped.append((m.name[:120], f"unwritable: {type(e).__name__}"))
    except tarfile.TarError as e:
        raise ValueError(f"could not read tar: {e}") from e
    side.close()
    return out
