"""
AegisPilot - read only the Python files of a remote wheel (HTTP Range).

Why: scanning needs a wheel's `.py` / `.pth` files, but the current path downloads the whole archive into memory
and unpacks everything. Large wheels (tensorflow 223 MB, torch 124 MB) are mostly compiled binaries the scanner
never reads. A wheel is a zip file, and a zip keeps its file table at the END, so:
  1. read the tail (end-of-central-directory + central directory)       -> every member's name/offset/size
  2. pick the members we analyze (`.py`, `.pth`)
  3. fetch only those byte ranges, merging neighbours, a few in parallel
  4. inflate each member (CRC-checked) into a temp dir laid out like the normal extraction

Anything unexpected (server ignores Range, zip64 oddities, encrypted member, CRC mismatch, limits exceeded) raises
RemoteWheelError and the caller falls back to the normal full download - this is an optimization, never a gate.
Nothing downloaded is executed or imported.
"""
from __future__ import annotations

import io
import struct
import urllib.request
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import safe_extract
from safe_extract import ArchiveLimitError

WANTED_SUFFIXES = (".py", ".pth")
MAX_MEMBER_BYTES = safe_extract.MAX_MEMBER_BYTES   # same limits as the full-download path (see safe_extract)
MAX_TOTAL_BYTES = safe_extract.MAX_TOTAL_BYTES
MAX_TAIL_BYTES = 8 * 1024 * 1024           # central directory we are willing to read
MERGE_GAP_BYTES = 256 * 1024               # wasted bytes we accept to join two wanted ranges into one request
MAX_RANGE_BYTES = 16 * 1024 * 1024         # one request never asks for more than this
PARALLEL_REQUESTS = 8
REQUEST_TIMEOUT = 30

_LOCAL_HEADER = struct.Struct("<4s5H3L2H")  # zip local file header, 30 bytes


class RemoteWheelError(Exception):
    pass


def _get_range(url: str, start: int, end: int) -> bytes:
    """Bytes [start, end] inclusive. Requires a 206 answer: a server that ignores Range would send the whole file."""
    req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        if resp.status != 206:
            raise RemoteWheelError(f"server did not honour Range (status {resp.status})")
        data = resp.read(end - start + 2)
    if len(data) != end - start + 1:
        raise RemoteWheelError(f"short range read ({len(data)} of {end - start + 1})")
    return data


def _total_size(url: str) -> int:
    req = urllib.request.Request(url, headers={"Range": "bytes=0-0"})
    with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        if resp.status != 206:
            raise RemoteWheelError(f"server did not honour Range (status {resp.status})")
        cr = resp.headers.get("Content-Range", "")           # "bytes 0-0/223229342"
        resp.read(2)
    try:
        return int(cr.rsplit("/", 1)[1])
    except (IndexError, ValueError):
        raise RemoteWheelError(f"no usable Content-Range: {cr!r}")


class _TailFile(io.RawIOBase):
    """Just enough of a file for zipfile to read the central directory from a downloaded tail."""

    def __init__(self, tail: bytes, total: int):
        self._tail, self._base, self._total, self._pos = tail, total - len(tail), total, 0

    def seekable(self): return True
    def readable(self): return True
    def tell(self): return self._pos

    def seek(self, off, whence=0):
        self._pos = {0: off, 1: self._pos + off, 2: self._total + off}[whence]
        return self._pos

    def read(self, n=-1):
        end = self._total if n is None or n < 0 else min(self._pos + n, self._total)
        if self._pos < self._base:
            raise RemoteWheelError("zipfile asked for bytes before the downloaded tail")
        out = self._tail[self._pos - self._base:end - self._base]
        self._pos = end
        return out


def _read_central_directory(url: str, total: int, counter: dict) -> tuple[list[zipfile.ZipInfo], int]:
    """(members, offset where the central directory starts)."""
    tail_len = min(total, 256 * 1024)
    while True:
        tail = _get_range(url, total - tail_len, total - 1)
        counter["requests"] += 1
        counter["bytes"] += len(tail)
        try:
            zf = zipfile.ZipFile(_TailFile(tail, total))
            return zf.infolist(), zf.start_dir
        except (RemoteWheelError, zipfile.BadZipFile):
            # central directory (or its zip64 locator) is longer than what we fetched: grow, within a limit
            if tail_len >= min(total, MAX_TAIL_BYTES):
                raise RemoteWheelError("central directory too large or unreadable")
            tail_len = min(total, tail_len * 4, MAX_TAIL_BYTES)


def _plan(infos: list[zipfile.ZipInfo], start_dir: int) -> tuple[list[tuple[zipfile.ZipInfo, int, int]], list[list]]:
    """Region [start, end) of every wanted member (local header + data) and merged request groups.
    A member's region ends where the next member (or the central directory) begins."""
    by_offset = sorted(infos, key=lambda i: i.header_offset)
    ends = {}
    for a, b in zip(by_offset, by_offset[1:]):
        ends[a.filename] = b.header_offset
    ends[by_offset[-1].filename] = start_dir
    wanted = [(i, i.header_offset, ends[i.filename]) for i in by_offset       # the same choice as a full download
              if not i.is_dir() and safe_extract.member_policy(i.filename, i.file_size) == "extract"]
    groups: list[list] = []
    for w in wanted:
        if groups and w[1] - groups[-1][-1][2] <= MERGE_GAP_BYTES and w[2] - groups[-1][0][1] <= MAX_RANGE_BYTES:
            groups[-1].append(w)
        else:
            groups.append([w])
    return wanted, groups


def fetch_python_files(url: str, dest_dir: Path, archive_name: str) -> tuple[list[Path], dict]:
    """Download only the `.py`/`.pth` members of the wheel at `url` into
    dest_dir/<archive_name>.unpacked/..., returning (paths, stats). Raises RemoteWheelError to ask for a fallback."""
    total = _total_size(url)
    counter = {"requests": 1, "bytes": 1}
    infos, start_dir = _read_central_directory(url, total, counter)
    if not infos:
        raise RemoteWheelError("empty archive")
    if any(i.flag_bits & 0x1 for i in infos):
        raise RemoteWheelError("encrypted members")
    wanted, groups = _plan(infos, start_dir)
    if len(infos) > safe_extract.MAX_MEMBERS:
        raise ArchiveLimitError(f"archive limit exceeded: {len(infos)} files (limit {safe_extract.MAX_MEMBERS})")
    for i, _, _ in wanted:                                  # size / compression-ratio limits end in REVIEW, not in a retry
        safe_extract.check_member(i.filename, i.file_size, i.compress_size)
    if sum(i.file_size for i, _, _ in wanted) > MAX_TOTAL_BYTES:
        raise ArchiveLimitError(f"archive limit exceeded: extracted files total more than {MAX_TOTAL_BYTES >> 20}MB")

    def fetch_group(g):
        start, end = g[0][1], g[-1][2]
        return start, _get_range(url, start, min(end, total) - 1)

    with ThreadPoolExecutor(PARALLEL_REQUESTS) as ex:
        buffers = list(ex.map(fetch_group, groups))
    counter["requests"] += len(groups)
    counter["bytes"] += sum(len(b) for _, b in buffers)

    root = dest_dir / (archive_name + ".unpacked")
    root.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    skipped: list = []
    for (start, buf), g in zip(buffers, groups):
        for info, m_start, _ in g:
            off = m_start - start
            hdr = _LOCAL_HEADER.unpack_from(buf, off)
            if hdr[0] != b"PK\x03\x04":
                raise RemoteWheelError(f"bad local header for {info.filename}")
            name_len, extra_len = hdr[9], hdr[10]
            data = buf[off + _LOCAL_HEADER.size + name_len + extra_len: off + _LOCAL_HEADER.size + name_len + extra_len + info.compress_size]
            if info.compress_type == zipfile.ZIP_STORED:
                content = data
            elif info.compress_type == zipfile.ZIP_DEFLATED:
                d = zlib.decompressobj(-15)
                content = d.decompress(data, info.file_size + 1)
                if d.unconsumed_tail:
                    raise RemoteWheelError(f"{info.filename} inflates beyond its declared size")
            else:
                raise RemoteWheelError(f"unsupported compression {info.compress_type}")
            if len(content) != info.file_size or (zlib.crc32(content) & 0xFFFFFFFF) != info.CRC:
                raise RemoteWheelError(f"corrupt member {info.filename}")
            rel, why = safe_extract.clean_member_name(info.filename)
            if rel is None:
                skipped.append((info.filename[:120], why))
                continue
            target = safe_extract._target(root, rel)       # re-checks that the real path stays under root
            if target is None:
                skipped.append((info.filename[:120], "resolves outside the extraction dir"))
                continue
            try:
                target.write_bytes(content)
            except OSError as e:
                skipped.append((info.filename[:120], f"unwritable: {type(e).__name__}"))
                continue
            out.append(target)
    # members whose name is the signal (README, .pyc, big placed files): an empty file, nothing downloaded
    for info in infos:
        if not info.is_dir() and safe_extract.member_policy(info.filename, info.file_size) == "marker":
            rel, _ = safe_extract.clean_member_name(info.filename)
            target = safe_extract._target(root, rel) if rel is not None else None
            if target is not None:
                target.touch()
    stats = {"archive_bytes": total, "bytes_transferred": counter["bytes"], "requests": counter["requests"],
             "members_total": len(infos), "members_fetched": len(out), "range_groups": len(groups), "skipped": skipped}
    return out, stats
