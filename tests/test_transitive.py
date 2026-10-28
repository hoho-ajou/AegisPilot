"""Transitive dependencies (run: python3 tests/test_transitive.py). No network: PyPI and OSV are replaced."""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(GUARD))
import collect  # noqa: E402
import guard_core  # noqa: E402,F401  (loads the guard modules the checks use)
from checks import pypi as check_pypi  # noqa: E402
from checks.base import Outcome  # noqa: E402
import scan_engine as se  # noqa: E402
import transitive  # noqa: E402

NOW = datetime(2026, 10, 23, tzinfo=timezone.utc)


def release(days_ago: float, yanked=False):
    t = (NOW - timedelta(days=days_ago)).isoformat().replace("+00:00", "Z")
    return [{"upload_time_iso_8601": t, "yanked": yanked}]


META = {
    "lib-a": {"info": {"version": "2.0"}, "releases": {"1.0": release(900), "2.0": release(3), "3.0b1": release(1)}},
    "lib-b": {"info": {"version": "1.5"}, "releases": {"1.4": release(400), "1.5": release(200, yanked=True)}},
    "lib-c": {"info": {"version": "0.9"}, "releases": {"0.9": release(10)}},
}
REQUIRES = {("lib-a", "2.0"): [{"name": "lib-c", "spec": ""}], ("lib-a", "1.0"): [], ("lib-b", "1.4"): [],
            ("lib-c", "0.9"): [{"name": "lib-a", "spec": ""}]}       # a cycle back to lib-a


class Walk(unittest.TestCase):
    def setUp(self):
        self._req = collect.fetch_requires
        collect.fetch_requires = lambda name, version, meta, **k: REQUIRES.get((name, version), [])

    def tearDown(self):
        collect.fetch_requires = self._req

    def test_pick_version_like_pip(self):
        self.assertEqual(transitive.pick_version(META["lib-a"], ""), "2.0")          # newest final, not the beta
        self.assertEqual(transitive.pick_version(META["lib-a"], "<2"), "1.0")
        self.assertEqual(transitive.pick_version(META["lib-a"], ">=3.0b1"), "3.0b1")  # a range naming a pre-release
        self.assertEqual(transitive.pick_version(META["lib-b"], ""), "1.4")          # yanked 1.5 is skipped
        self.assertIsNone(transitive.pick_version(META["lib-b"], ">5"))

    def test_walk_follows_the_tree_marks_recent_and_stops_on_cycles(self):
        direct = [{"name": "app", "version": "1", "dependencies": [{"name": "lib-a", "spec": ""}, {"name": "lib-b", "spec": ""}]}]
        found, notes = transitive.walk(direct, lambda n: META[n], now=NOW)
        got = {r["name"]: (r["version"], r["recent"], " → ".join(r["via"])) for r in found}
        self.assertEqual(got, {"lib-a": ("2.0", True, "app"), "lib-b": ("1.4", False, "app"),
                               "lib-c": ("0.9", True, "app → lib-a")})
        self.assertEqual(notes, [])

    def test_lock_pins_win_and_limits_are_reported(self):
        direct = [{"name": "app", "version": "1", "dependencies": [{"name": "lib-a", "spec": ""}, {"name": "lib-b", "spec": ""}]}]
        found, _ = transitive.walk(direct, lambda n: META[n], lock_pins={"lib-a": "1.0"}, now=NOW)
        self.assertEqual({r["name"]: r["version"] for r in found}["lib-a"], "1.0")
        cfg = dict(transitive.settings())
        try:
            transitive.settings().update(max_packages=1)
            found, notes = transitive.walk(direct, lambda n: META[n], now=NOW)
            self.assertEqual(len(found), 1)
            self.assertTrue(any("not checked" in n for n in notes), notes)
        finally:
            transitive.settings().update(cfg)


class GuardCore(unittest.TestCase):
    def test_a_malicious_dependency_blocks_with_its_path(self):
        saved = (transitive.walk, transitive.osv_malicious, se.scan_packages)
        try:
            transitive.walk = lambda direct, fetch, pins, deadline=None: (
                [{"name": "evil-dep", "version": "6.6.6", "via": ["app"], "recent": False}], [])
            transitive.osv_malicious = lambda found: {("evil-dep", "6.6.6"): ["MAL-2026-1"]}

            def fake_scan(items, budget=None):
                out = []
                for n, v in items:
                    f = se.ScanFeatures(name=n, version=v, resolved_version=v, fetch_ok=True)
                    f.osv_vulns = [{"id": "MAL-2026-1", "summary": "Malicious code in evil-dep"}]
                    out.append(se.Verdict("ALLOW", 0.0, [], f))
                return out
            se.scan_packages = fake_scan
            app = se.ScanFeatures(name="app", version="1", resolved_version="1", fetch_ok=True)
            app.dependencies = [{"name": "evil-dep", "spec": ""}]

            class P:
                packages, lock_pins = [("app", "1")], {}
            out = Outcome()
            info = check_pypi.transitive(P, [se.Verdict("ALLOW", 0.0, [], app)], True, out)
            blocked = [rec for rec, verdict in out.dependencies if verdict == "BLOCK"]
            self.assertEqual(info["malicious"], 1)
            self.assertEqual(len(blocked), 1)
            self.assertEqual(blocked[0]["via"], "app → evil-dep")
            self.assertEqual(blocked[0]["evidence"][0]["rule"], "known_malicious")
        finally:
            transitive.walk, transitive.osv_malicious, se.scan_packages = saved

    def test_failure_never_raises(self):
        saved = transitive.walk
        try:
            def boom(*a, **k):
                raise RuntimeError("network down")
            transitive.walk = boom
            app = se.ScanFeatures(name="app", version="1", fetch_ok=True)
            app.dependencies = [{"name": "x", "spec": ""}]

            class P:
                packages, lock_pins = [("app", "1")], {}
            info = check_pypi.transitive(P, [se.Verdict("ALLOW", 0.0, [], app)], True, Outcome())
            self.assertIn("RuntimeError", info["error"])
        finally:
            transitive.walk = saved


if __name__ == "__main__":
    unittest.main()
