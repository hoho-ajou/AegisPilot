"""npm dependencies that run code at install are scanned too (sources/npm.install_script_deps / lock_install_scripts,
guard_core._check_npm_script_deps; 2026-10-23). Offline: the registry and the scans are faked.
run: python3 tests/test_npm_deps.py"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.update({"HOME": tempfile.mkdtemp(), "AEGIS_ML": "0", "AEGIS_MODE": "auto"})
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import guard_core  # noqa: E402
import scan_engine as se  # noqa: E402
from sources import npm  # noqa: E402

guard_core.check_integrity = lambda: []

# a registry: app -> lib -> (evil-native: install script), app -> fsevents (optional, install script), clean-native has one too
REG = {
    "app": {"1.0.0": {"dependencies": {"lib": "^2.0.0"}, "optionalDependencies": {"fsevents": "^2.3.0"}}},
    "lib": {"2.0.0": {"dependencies": {"evil-native": "~1.0.0"}}, "2.1.0": {"dependencies": {"evil-native": "~1.0.0", "clean-native": "1.x"}}},
    "evil-native": {"1.0.3": {"hasInstallScript": True}},
    "clean-native": {"1.2.0": {"hasInstallScript": True}},
    "fsevents": {"2.3.3": {"hasInstallScript": True}},
}


def fake_metadata(name):
    if name not in REG:
        raise OSError("HTTP Error 404")
    return {"name": name, "dist-tags": {"latest": max(REG[name], key=npm.parse)}, "versions": REG[name]}


npm.metadata = fake_metadata
npm._publish_times = lambda name: {}          # no publish times: no dependency counts as recently published
found, notes = npm.install_script_deps([("app", None)], time.monotonic() + 10, skip={"app"})
got = {(f["name"], f["version"], f["via"]) for f in found}
assert got == {("evil-native", "1.0.3", "app"), ("clean-native", "1.2.0", "app"), ("fsevents", "2.3.3", "app")}, got
assert notes == []
assert npm.install_script_deps([("app", None)], time.monotonic() - 1)[1]               # out of time: noted, not raised
npm.TREE_MAX_PACKAGES, keep = 2, npm.TREE_MAX_PACKAGES                                 # the limit counts distinct packages
assert "only the first 2 " in " ".join(npm.install_script_deps([("app", None)], time.monotonic() + 10)[1])
npm.TREE_MAX_PACKAGES = keep

lock = {"packages": {"": {}, "node_modules/a": {"version": "1.0.0"},
                     "node_modules/a/node_modules/b": {"version": "2.0.0", "hasInstallScript": True},
                     "node_modules/c": {"version": "3.0.0", "hasInstallScript": True},
                     "node_modules/d": {"version": "1.0.0", "hasInstallScript": True, "link": True}}}
assert npm.lock_install_scripts(lock) == [{"name": "b", "version": "2.0.0", "via": "a"}, {"name": "c", "version": "3.0.0", "via": None}]


# files an install script runs are install-time code (attack paths: "at install", not "when the package is used")
with tempfile.TemporaryDirectory() as t:
    pj = Path(t, "package", "package.json")
    pj.parent.mkdir()
    pj.write_text(json.dumps({"scripts": {"postinstall": "node ./scripts/post.js && sh setup.sh --x", "test": "node t.js",
                                          "prepare": "node build.mjs", "install": "node ../evil.js"}}))
    assert npm.install_time_files([pj]) == ["scripts/post.js", "setup.sh"]
    assert npm.install_time_files([pj], npm.LIFECYCLE + ("prepare",)) == ["scripts/post.js", "setup.sh", "build.mjs"]

# the decision: the dependency's install script is what is flagged; its record says which package pulls it in
def fake_scan(name, spec=None):
    f = se.ScanFeatures(name=name, version=spec, resolved_version=spec, ecosystem="npm", fetch_ok=True)
    if name == "evil-native":
        return se.Verdict("BLOCK", 1.0, ["[hard rule] reverse shell"], f)
    return se.Verdict("ALLOW", 0.0, [], f)


se.scan_npm_package = fake_scan
se.ECOSYSTEM_SCANNERS["npm"] = fake_scan
import post_rules  # noqa: E402
post_rules.osv_reachable = lambda *a, **k: True
asked = []
npm.malicious_releases = lambda pairs: asked.extend(pairs) or {}
with tempfile.TemporaryDirectory() as d:
    r = guard_core.check_command("npm install app", d)
    # the whole resolved tree went to OSV (not only the packages with install scripts), the named package excluded
    assert set(asked) == {("lib", "2.1.0"), ("evil-native", "1.0.3"), ("clean-native", "1.2.0"), ("fsevents", "2.3.3")}, asked
    doc = json.loads(Path(d, ".aegis", "last_review.json").read_text())
    assert r.action == "refuse" and doc["verdict"] == "BLOCK", (r, doc["verdict"])
    evil = [p for p in doc["packages"] if p["package"] == "evil-native"][0]
    assert evil["via"] == "app → evil-native" and evil["install_script_dependency"], evil
    assert doc["npm_dependency_scripts"]["scanned"] == 3 and doc["npm_dependency_scripts"]["from"] == "registry"
    assert doc["npm_dependency_scripts"]["tree_osv_checked"] == 4

# a malicious dependency with no install script (it does its harm when imported) is found by the tree's OSV check:
# BLOCK with the path that pulls it in; a malicious one with an install script is not scanned again
npm.malicious_releases = lambda pairs: {p: ["MAL-2025-1"] for p in pairs if p[0] in ("lib", "clean-native")}
with tempfile.TemporaryDirectory() as d:
    r = guard_core.check_command("npm install app", d)
    doc = json.loads(Path(d, ".aegis", "last_review.json").read_text())
    lib = [p for p in doc["packages"] if p["package"] == "lib"]
    assert r.action == "refuse" and lib and lib[0]["verdict"] == "BLOCK" and lib[0]["via"] == "app → lib", lib
    assert doc["npm_dependency_scripts"]["tree_malicious"] == 2 and doc["npm_dependency_scripts"]["scanned"] == 2

# OSV down: noted, the rest of the check stands
post_rules.osv_reachable = lambda *a, **k: False
with tempfile.TemporaryDirectory() as d:
    guard_core.check_command("npm install app", d)
    doc = json.loads(Path(d, ".aegis", "last_review.json").read_text())
    assert any("OSV could not be reached" in n for n in doc["npm_dependency_scripts"]["notes"]), doc["npm_dependency_scripts"]
post_rules.osv_reachable = lambda *a, **k: True
with tempfile.TemporaryDirectory() as d:

    # a project with a lock: the lock says which dependencies have install scripts (no registry walk)
    Path(d, "package.json").write_text(json.dumps({"dependencies": {"lib": "^2.0.0"}}))
    Path(d, "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/lib": {"version": "2.0.0"},
        "node_modules/evil-native": {"version": "1.0.3", "hasInstallScript": True}}}))
    npm.metadata = lambda name: (_ for _ in ()).throw(AssertionError("no registry walk with a lock"))
    npm.malicious_releases = lambda pairs: {}
    r = guard_core.check_command("npm install", d)
    doc = json.loads(Path(d, ".aegis", "last_review.json").read_text())
    assert r.action == "refuse" and doc["npm_dependency_scripts"]["from"] == "package-lock.json", doc.get("npm_dependency_scripts")

    # nothing with an install script: nothing more to scan
    Path(d, "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lib": {"version": "2.0.0"}}}))
    assert guard_core.check_command("npm install", d).action == "allow"

# a package built for another OS / CPU is skipped, as npm skips it (and what it pulls in)
here_os, here_cpu = npm._npm_platform()
assert npm.fits_platform({}) and npm.fits_platform({"os": [here_os], "cpu": [here_cpu]})
assert not npm.fits_platform({"os": ["!" + here_os]}) and not npm.fits_platform({"cpu": ["not-a-cpu"]})
REG["app"]["1.0.0"]["optionalDependencies"] = {"fsevents": "^2.3.0", "other-os": "1.0.0"}
REG["other-os"] = {"1.0.0": {"hasInstallScript": True, "os": ["not-this-os"]}}
npm.metadata = fake_metadata
found, _ = npm.install_script_deps([("app", None)], time.monotonic() + 10, skip={"app"})
assert "other-os" not in {f["name"] for f in found}, found

# recently published dependencies: only packages changed within the window are dated (their full document read)
from datetime import datetime, timedelta, timezone  # noqa: E402
now = datetime(2026, 11, 18, tzinfo=timezone.utc)
old, fresh = (now - timedelta(days=400)).isoformat(), (now - timedelta(days=2)).isoformat()
tree = [{"name": "stale", "version": "1.0.0", "via": "app", "modified": old},
        {"name": "fresh", "version": "3.1.0", "via": "app", "modified": fresh},
        {"name": "changed-old-version", "version": "2.0.0", "via": "app", "modified": fresh},
        {"name": "app", "version": "1.0.0", "via": None, "modified": fresh}]
dated = []


def times(name):
    dated.append(name)
    return {"fresh": {"3.1.0": fresh}, "changed-old-version": {"2.0.0": old}}.get(name, {})


npm._publish_times = times
recent, rnotes = npm.recent_releases(tree, 30, time.monotonic() + 10, skip={"app"}, now=now)
assert [d["name"] for d in recent] == ["fresh"], recent
assert sorted(dated) == ["changed-old-version", "fresh"], dated          # "stale" never fetched, "app" skipped
print("npm_deps: all cases passed")
