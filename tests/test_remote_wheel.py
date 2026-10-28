"""Offline tests for remote_wheel (run: python3 tests/test_remote_wheel.py). A local HTTP server speaks Range."""
import io
import os
import random
import re
import sys
import tempfile
import threading
import zipfile
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import remote_wheel as rw  # noqa: E402

from _wheel_server import PAYLOAD, make_wheel, serve  # noqa: E402


def fetch(url):
    with tempfile.TemporaryDirectory() as d:
        paths, stats = rw.fetch_python_files(url, Path(d), "pkg-1.0.whl")
        return {str(p.relative_to(Path(d) / "pkg-1.0.whl.unpacked")): p.read_bytes() for p in paths}, stats


# 1) only .py/.pth members, byte-identical, and far fewer bytes than the archive
blob = make_wheel()
srv, url, log = serve(blob)
files, st = fetch(url)
assert set(files) == {"pkg/__init__.py", "pkg/a.py", "pkg/b.py", "evil.pth"}, set(files)
assert files["pkg/a.py"] == PAYLOAD
assert st["bytes_transferred"] < len(blob) * 0.3, (st, len(blob))
assert st["members_total"] == 7 and st["members_fetched"] == 4
srv.shutdown()

# 1b) the same member choice as a full download (safe_extract.member_policy): a README's text is read (agent-directed
# text, 2026-10-23), a member that matters only by name (.pyc) is an empty marker, data is not downloaded
blob = make_wheel(extra={"pkg-1.0.dist-info/README.md": b"# readme\n" * 1000, "pkg/c.pyc": b"\x00" * 5000, "pkg/d.json": b"{}"})
srv, url, log = serve(blob)
with tempfile.TemporaryDirectory() as d:
    rw.fetch_python_files(url, Path(d), "pkg-1.0.whl")
    base = Path(d) / "pkg-1.0.whl.unpacked"
    assert (base / "pkg-1.0.dist-info" / "README.md").read_bytes() == b"# readme\n" * 1000
    assert (base / "pkg" / "c.pyc").stat().st_size == 0 and not (base / "pkg" / "d.json").exists()
srv.shutdown()

# 2) many adjacent small members are merged into a handful of requests, not one request each
blob = make_wheel(n_small=300)
srv, url, log = serve(blob)
files, st = fetch(url)
assert len([f for f in files if f.startswith("pkg/m")]) == 300
assert st["requests"] <= 12, st
srv.shutdown()

# 3) a server that ignores Range is refused (so the caller falls back instead of buffering a whole file)
srv, url, _ = serve(make_wheel(), honour_range=False)
try:
    fetch(url); raise SystemExit("should have refused")
except rw.RemoteWheelError as e:
    assert "Range" in str(e)
srv.shutdown()

# 4) corrupted bytes inside a wanted member -> CRC mismatch -> refuse
blob = make_wheel()
off = blob.index(PAYLOAD) if PAYLOAD in blob else None        # deflated, so search the stored header region instead
zf = zipfile.ZipFile(io.BytesIO(blob)); info = zf.getinfo("pkg/b.py")
srv, url, _ = serve(blob, corrupt_at=info.header_offset + 30 + len(info.filename) + 2)
try:
    fetch(url); raise SystemExit("corruption not detected")
except rw.RemoteWheelError as e:
    assert "corrupt" in str(e) or "inflates" in str(e) or "Error" in str(type(e).__name__), e
except zlib.error:
    pass                                                         # inflate failure is also a refusal; caller falls back
srv.shutdown()

# 5) a traversal member name is never written outside the extraction root
blob = make_wheel(extra={"../outside.py": b"z = 1\n"})
srv, url, _ = serve(blob)
with tempfile.TemporaryDirectory() as d:
    paths, _ = rw.fetch_python_files(url, Path(d), "pkg-1.0.whl")
    assert not (Path(d) / "outside.py").exists() and not any("outside" in str(p) for p in paths)
srv.shutdown()

# 6) python files declared larger than the limit are refused up front (zip-bomb guard). A limit is a verdict
#    (ArchiveLimitError -> REVIEW "not analyzed"), not a RemoteWheelError the caller would retry as a full download.
blob = make_wheel(extra={"pkg/huge.py": b"#" * (rw.MAX_MEMBER_BYTES + 10)})
srv, url, _ = serve(blob)
try:
    fetch(url); raise SystemExit("size limit not enforced")
except rw.ArchiveLimitError as e:
    assert "one file" in str(e)
srv.shutdown()

# 7) compression ratio: 2MB of zeros compresses ~1000x -> refused although far below the size limits
blob = make_wheel(extra={"pkg/bomb.py": bytes(2 * 1024 * 1024)})
srv, url, _ = serve(blob)
try:
    fetch(url); raise SystemExit("ratio limit not enforced")
except rw.ArchiveLimitError as e:
    assert "compression ratio" in str(e), e
srv.shutdown()

# 8) an unsafe member name is skipped and reported; the other files are still analyzed
blob = make_wheel(extra={"../up.py": b"x = 1\n", "ok/fine.py": b"y = 2\n"})
srv, url, _ = serve(blob)
with tempfile.TemporaryDirectory() as d:
    paths, stats = rw.fetch_python_files(url, Path(d), "w-1.0-py3-none-any.whl")
    assert any(p.name == "fine.py" for p in paths) and not (Path(d) / "up.py").exists()
    assert stats["skipped"] and "traversal" in stats["skipped"][0][1], stats["skipped"]
srv.shutdown()

print("remote_wheel: all cases passed")
