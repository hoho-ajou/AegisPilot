"""Offline tests for how scan_engine uses remote_wheel (run: python3 tests/test_range_integration.py)."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import scan_engine as se  # noqa: E402
from sources import pypi  # noqa: E402
from _wheel_server import make_wheel, serve  # noqa: E402


def run(honour_range, size_field, min_bytes, cap=None):
    blob = make_wheel(binary_mb=4)
    srv, url, log = serve(blob, honour_range=honour_range)
    meta = {"info": {"version": "1.0"}, "releases": {"1.0": [{"packagetype": "bdist_wheel", "filename": "pkg-1.0-py3-none-any.whl", "url": url, "size": size_field}]}}
    real = (pypi.metadata, pypi.RANGE_MIN_BYTES, pypi.MAX_DOWNLOAD_BYTES, pypi.FILES_HOST)
    pypi.metadata = lambda n: meta
    pypi.FILES_HOST = url.rsplit("/", 1)[0]                 # the local test server stands in for files.pythonhosted.org
    pypi.RANGE_MIN_BYTES = min_bytes
    if cap:
        pypi.MAX_DOWNLOAD_BYTES = cap
    try:
        with tempfile.TemporaryDirectory() as d:
            resolved, files = pypi.fetch("pkg", "1.0", Path(d))
            names = sorted(str(p.relative_to(Path(d) / "pkg-1.0-py3-none-any.whl.unpacked")) for p in files if p.is_file())
            return resolved, names, len(log)
    finally:
        pypi.metadata, pypi.RANGE_MIN_BYTES, pypi.MAX_DOWNLOAD_BYTES, pypi.FILES_HOST = real
        srv.shutdown()


# a large wheel on a Range-capable server: only python files (and no whole-file download)
_, names, n_ranges = run(True, size_field=50 * 2**20, min_bytes=1)
assert names == ["evil.pth", "pkg/__init__.py", "pkg/a.py", "pkg/b.py"], names
assert n_ranges >= 2

# the same wheel when the server ignores Range: falls back to the full download, which also unpacks only the files
# the analysis reads (safe_extract) - no data/binary members are written
_, names, n_ranges = run(False, size_field=50 * 2**20, min_bytes=1)
assert names == ["evil.pth", "pkg/__init__.py", "pkg/a.py", "pkg/b.py"], names

# below the threshold the plain download is used (extra requests would cost more than they save)
_, names, n_ranges = run(True, size_field=2 * 2**20, min_bytes=16 * 2**20)
assert names == ["evil.pth", "pkg/__init__.py", "pkg/a.py", "pkg/b.py"] and n_ranges == 0, (names, n_ranges)

# the size cap protects the full download only; reading just the python files of an over-cap wheel is fine
_, names, _ = run(True, size_field=300 * 2**20, min_bytes=1, cap=1024)
assert names == ["evil.pth", "pkg/__init__.py", "pkg/a.py", "pkg/b.py"], names
try:
    run(False, size_field=300 * 2**20, min_bytes=1, cap=1024)       # no Range -> full path -> cap applies
    raise SystemExit("cap not applied on the full-download path")
except ValueError as e:
    assert "too large" in str(e)

print("range integration: all cases passed")
