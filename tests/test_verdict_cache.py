"""Verdict cache (run: python3 tests/test_verdict_cache.py). Offline: registry, download and OSV are fakes."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import scan_engine as se  # noqa: E402
import verdict_cache as VC  # noqa: E402
from sources import pypi  # noqa: E402

OLD = "2024-01-01T00:00:00Z"
WHEEL = {"filename": "good-2.0-py3-none-any.whl", "packagetype": "bdist_wheel", "url": "https://files.pythonhosted.org/w",
         "size": 10, "upload_time_iso_8601": OLD, "yanked": False, "digests": {"sha256": "a" * 64}}
SDIST = {"filename": "good-2.0.tar.gz", "packagetype": "sdist", "url": "https://files.pythonhosted.org/s",
         "size": 10, "upload_time_iso_8601": OLD, "yanked": False, "digests": {"sha256": "b" * 64}}
META = {"info": {"version": "2.0"}, "releases": {"2.0": [WHEEL, SDIST]}}

scans, osv = [], {}
saved = (pypi.metadata, se._scan_release, se.query_osv)


def fake_release(features, eco, version, fetch, release, ml, finish):
    scans.append((features.name, version))
    features.fetch_ok = True
    return se.Verdict("ALLOW", 0.0, [], features)


try:
    pypi.metadata = lambda n: META
    se._scan_release = fake_release
    se.query_osv = lambda name, version, *a: list(osv.get((name, version), []))
    os.environ.pop("AEGIS_CACHE", None)
    with tempfile.TemporaryDirectory() as d:
        # a lone scan (no command scope): never reads or writes the cache
        se.scan_package("good", "2.0")
        se.scan_package("good", "2.0")
        assert len(scans) == 2 and not (Path(d) / ".aegis/cache/verdicts.json").exists()

        # within commands: the second one reuses the ALLOW for the same file
        VC.begin(d); v1 = se.scan_package("good", "2.0"); VC.end()
        VC.begin(d); v2 = se.scan_package("good", "2.0"); VC.end()
        assert len(scans) == 3 and v2.verdict == "ALLOW" and v2.features.from_cache, scans
        doc = json.loads((Path(d) / ".aegis/cache/verdicts.json").read_text())
        (k,) = doc["entries"]
        assert k == "pypi:good==2.0#good-2.0-py3-none-any.whl:" + "a" * 64, k      # the wheel pip installs, by hash

        # a file added to the release that pip now prefers (another wheel name): a new key, scanned again
        META["releases"]["2.0"] = [dict(WHEEL, filename="good-2.0-py2.py3-none-any.whl", digests={"sha256": "c" * 64}),
                                   SDIST]
        VC.begin(d); se.scan_package("good", "2.0"); VC.end()
        assert len(scans) == 4
        META["releases"]["2.0"] = [WHEEL, SDIST]

        # OSV has a record now: never reused (scanned again)
        osv[("good", "2.0")] = [{"id": "GHSA-x"}]
        VC.begin(d); se.scan_package("good", "2.0"); VC.end()
        assert len(scans) == 5
        osv.clear()

        # other rules / models / guard: the cache starts empty
        doc = json.loads((Path(d) / ".aegis/cache/verdicts.json").read_text())
        doc["fp"] = "other-guard"
        (Path(d) / ".aegis/cache/verdicts.json").write_text(json.dumps(doc))
        VC.begin(d); se.scan_package("good", "2.0"); VC.end()
        assert len(scans) == 6
        assert json.loads((Path(d) / ".aegis/cache/verdicts.json").read_text())["fp"] == VC.fingerprint()

        # expired entries are scanned again
        doc = json.loads((Path(d) / ".aegis/cache/verdicts.json").read_text())
        for e in doc["entries"].values():
            e["t"] = time.time() - VC.TTL_SECONDS - 1
        (Path(d) / ".aegis/cache/verdicts.json").write_text(json.dumps(doc))
        VC.begin(d); se.scan_package("good", "2.0"); VC.end()
        assert len(scans) == 7

        # a release under a day old is never cached
        fresh = dict(WHEEL, upload_time_iso_8601=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        META["releases"]["3.0"] = [fresh]
        VC.begin(d); se.scan_package("good", "3.0"); VC.end()
        VC.begin(d); se.scan_package("good", "3.0"); VC.end()
        assert scans[-2:] == [("good", "3.0"), ("good", "3.0")]

        # every finished verdict is stored (a held package is held again at once); failed and stopped scans are not
        VC.begin(d)
        k2 = VC.key("pypi", "bad", "1.0", "x.whl:1")
        VC.put(k2, se.Verdict("NEEDS_HUMAN_REVIEW", 0.5, [], se.ScanFeatures(name="bad", version="1.0", fetch_ok=True)))
        assert VC.get(k2).verdict == "NEEDS_HUMAN_REVIEW"
        k3 = VC.key("pypi", "flaky", "1.0", "x.whl:2")
        VC.put(k3, se.Verdict("ALLOW", 0.0, [], se.ScanFeatures(name="flaky", version="1.0", fetch_error="network")))
        stopped = se.ScanFeatures(name="stopped", version="1.0", fetch_ok=True)
        stopped.command_stopped = True
        VC.put(VC.key("pypi", "stopped", "1.0", "x.whl:3"), se.Verdict("NEEDS_HUMAN_REVIEW", 0.5, [], stopped))
        assert VC.get(k3) is None and VC.get(VC.key("pypi", "stopped", "1.0", "x.whl:3")) is None

        # auto mode "as is": the same held versions within 30 minutes, then the hold has to come again
        hk = ["pypi:bad==1.0"]
        assert not VC.held_before(hk)
        VC.note_held(hk)
        assert VC.held_before(hk) and not VC.held_before(hk + ["pypi:other==1.0"])
        VC.forget_held(hk)
        assert not VC.held_before(hk)
        VC.end()

        # a damaged file is a miss, never a crash; AEGIS_CACHE=0 turns it off
        (Path(d) / ".aegis/cache/verdicts.json").write_text("{broken")
        VC.begin(d); se.scan_package("good", "2.0"); VC.end()
        os.environ["AEGIS_CACHE"] = "0"
        assert not VC.enabled()
        os.environ.pop("AEGIS_CACHE")
        assert VC.enabled()
        assert VC.key("pypi", "x", ">=1.0", "f") is None and VC.key("pypi", "x", "1.0", None) is None
finally:
    pypi.metadata, se._scan_release, se.query_osv = saved
print("verdict_cache: all cases passed")

# the decision: auto mode goes ahead when the same held version comes back within 30 minutes (once), user mode asks
# every time, a BLOCK never goes ahead
import guard_core  # noqa: E402


def fake_scan(items, budget=None, workers=None):
    out = []
    for n, v in items:
        f = se.ScanFeatures(name=n, version=v, resolved_version=v, fetch_ok=True)
        verdict = {"held": "NEEDS_HUMAN_REVIEW", "evil": "BLOCK"}.get(n, "ALLOW")
        out.append(se.Verdict(verdict, 0.5, ["test hold"], f))
    return out


keep = guard_core.scan_packages
guard_core.scan_packages = fake_scan
import post_rules  # noqa: E402
post_rules.osv_reachable = lambda *a, **k: True
try:
    for mode, expect in (("auto", ["refuse", "allow", "refuse"]), ("user", ["confirm", "confirm", "confirm"])):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".aegis").mkdir()
            Path(d, ".aegis", "policy.json").write_text(json.dumps({"mode": mode}))
            got = [guard_core.check_command("pip install held==1.0 good==2.0", d).action for _ in range(3)]
            assert got == expect, (mode, got)
    with tempfile.TemporaryDirectory() as d:
        Path(d, ".aegis").mkdir()
        Path(d, ".aegis", "policy.json").write_text(json.dumps({"mode": "auto"}))
        got = [guard_core.check_command("pip install evil==1.0", d).action for _ in range(2)]
        assert got == ["refuse", "refuse"], got
        r = guard_core.check_command("pip install held==1.0", d)
        r2 = guard_core.check_command("pip install held==1.0", d)
        assert r2.action == "allow" and "went ahead" in r2.notice, r2
finally:
    guard_core.scan_packages = keep
print("verdict_cache decisions: all cases passed")
