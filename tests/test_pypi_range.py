"""A PyPI version range is scanned at the version pip installs, not the latest (run: python3 tests/test_pypi_range.py)."""
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(IMPL))

import install_parse  # noqa: E402
import scan_engine  # noqa: E402
from checks import pypi as check_pypi  # noqa: E402
from sources import pypi as src_pypi  # noqa: E402

F = [{"filename": "x.whl"}]
Y = [{"filename": "x.whl", "yanked": True}]
META = {"releases": {"2.25.1": F, "2.28.0": F, "2.28.2": F, "2.29.0": F, "2.29.1": Y, "2.30.0rc1": F,
                     "2.31.0": F, "3.0.0": [], "bad version!": F}}
pick = scan_engine.pypi_version_for_range
assert pick(META, "<2.30") == "2.29.0", pick(META, "<2.30")                # a yanked release is skipped
assert pick(META, "~=2.28.0") == "2.28.2"
assert pick(META, "==2.28.*") == "2.28.2"
assert pick(META, ">=2.20,<2.26") == "2.25.1"
assert pick(META, ">=2.31") == "2.31.0"                                     # a release with no files is skipped
assert pick(META, ">=2.30.0rc1,<2.31") == "2.30.0rc1"                       # a pre-release only when the range names one
assert pick(META, "<2.30 ; python_version > '3'") == "2.29.0"               # a marker is not part of the range
assert pick(META, "<1") is None
assert pick(META, "not a range") is None
print("pypi_range: versions picked as pip does")

# the check replaces the range with the version picked; a pinned version and a bare name stay as they are
src_pypi.metadata = lambda name: META
with tempfile.TemporaryDirectory() as d:
    Path(d, "requirements.txt").write_text("requests>=2.20,<2.26\nflask\nidna==3.4\n")
    p = install_parse.parse_install_command('pip install "urllib3<2.30" -r requirements.txt', cwd=d)
    check_pypi._pin_ranges(p)
    got = dict(p.packages)
    assert got == {"urllib3": "2.29.0", "requests": "2.25.1", "flask": None, "idna": "3.4"}, got


def fail(name):
    raise OSError("offline")


src_pypi.metadata = fail
p = install_parse.parse_install_command('pip install "requests<2.30"')
check_pypi._pin_ranges(p)
assert p.packages == [("requests", None)], p.packages                     # PyPI unreachable: the scan reports that itself
print("pypi_range: ranges in commands and requirements files resolved")
