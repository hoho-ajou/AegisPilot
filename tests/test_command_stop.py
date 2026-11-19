"""One command = one decision: once a package of it is a BLOCK, the other scans stop (scan_engine.COMMAND_STOP), the
packages stopped that way are REVIEWs that say so (never a pass), and the messages show only the BLOCK."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import scan_engine as se  # noqa: E402
from output import render as M  # noqa: E402
from sources import pypi  # noqa: E402

MAL = [{"id": "MAL-2026-1"}]
saved = (pypi.metadata, se.query_osv)
try:
    # a lone scan (guard_cli scan, the benchmark): a BLOCK never stops the next scan
    se.COMMAND_STOP.clear()

    def gone0(name):
        raise OSError("HTTP Error 404: Not Found")
    pypi.metadata = gone0
    se.query_osv = lambda name, version, *a: list(MAL) if (name, version) == ("evx", "1.0") else []
    assert se.scan_package("evx", "1.0").verdict == "BLOCK" and not se.COMMAND_STOP.is_set()

    # inside one command's decision: a release the registry no longer has, which OSV lists as malicious, is a BLOCK
    # from the scan, and the command's other scans stop
    se.command_begin()

    def gone(name):
        raise OSError("HTTP Error 404: Not Found")
    pypi.metadata = gone
    se.query_osv = lambda name, version, *a: list(MAL) if (name, version) == ("evx", "1.0") else []
    v = se.scan_package("evx", "1.0")
    assert v.verdict == "BLOCK" and v.features.verdict_rules == ["known_malicious"], (v.verdict, v.reasons)
    assert se.COMMAND_STOP.is_set()

    # any later package of the same command: not scanned, a REVIEW that says why (never ALLOW)
    other = se.scan_package("requests", "2.32.3")
    assert other.verdict == "NEEDS_HUMAN_REVIEW" and other.features.command_stopped, other.verdict
    assert se.COMMAND_STOP_NOTE in other.reasons
    npm_other = se.scan_npm_package("left-pad", "1.3.0")
    assert npm_other.verdict == "NEEDS_HUMAN_REVIEW" and npm_other.features.command_stopped

    # removed but not listed by OSV (or a range): the "could not fetch" REVIEW stays and nothing stops
    se.command_end()
    se.command_begin()
    v2 = se.scan_package("other-gone", "1.0")
    assert v2.verdict == "NEEDS_HUMAN_REVIEW" and not se.COMMAND_STOP.is_set()
    assert se._removed_release(se.ScanFeatures(name="evx", version=None), "pypi", ">=1.0") is None
finally:
    pypi.metadata, se.query_osv = saved
    se.command_end()
assert not se.COMMAND_STOP.is_set() and not se._COMMAND_ACTIVE.is_set()

# the messages: with a BLOCK, the packages stopped by it are not shown (they are in the record)
report = {"packages": [{"package": "evx", "version": "1.0", "verdict": "BLOCK"},
                       {"package": "jupyter", "version": "1.1", "verdict": "NEEDS_HUMAN_REVIEW", "command_stopped": True},
                       {"package": "pyyaml", "version": "5.3.1", "verdict": "NEEDS_HUMAN_REVIEW"}]}
shown, _ = M._split_packages(report)
assert [p["package"] for p in shown] == ["evx", "pyyaml"], shown
# without a BLOCK (a person's allow list lifted it), a stopped package is shown: it was not read
lifted = {"packages": [{**report["packages"][0], "verdict": "ALLOW"}, report["packages"][1]]}
assert [p["package"] for p in M._split_packages(lifted)[0]] == ["jupyter"]

# every command starts with the signal off (guard_core.check_parsed opens a fresh scope)
import tempfile  # noqa: E402
import guard_core  # noqa: E402
se.COMMAND_STOP.set()
with tempfile.TemporaryDirectory() as d:
    seen = []
    keep = se.scan_packages

    def fake(items, budget=None, workers=None):
        seen.append(se.COMMAND_STOP.is_set())
        return [se.Verdict("ALLOW", 0.0, [], se.ScanFeatures(name=n, version=v, resolved_version=v, fetch_ok=True))
                for n, v in items]
    se.scan_packages = fake
    guard_core.scan_packages = fake
    try:
        guard_core.check_command("pip install somepkg==1.0", d)
    finally:
        se.scan_packages = guard_core.scan_packages = keep
    assert seen and seen[0] is False, seen
se.COMMAND_STOP.clear()
print("ok")
