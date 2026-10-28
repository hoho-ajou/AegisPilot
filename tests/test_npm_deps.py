"""npm dependencies that run code at install are scanned too (sources/npm.install_script_deps / lock_install_scripts,
guard_core._check_npm_script_deps; 2026-10-23). Offline: the registry and the scans are faked.
run: python3 tests/test_npm_deps.py"""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.update({"HOME": tempfile.mkdtemp(), "AASM_ML": "0", "AASM_MODE": "auto"})
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
with tempfile.TemporaryDirectory() as d:
    r = guard_core.check_command("npm install app", d)
    doc = json.loads(Path(d, ".aasm", "last_review.json").read_text())
    assert r.action == "refuse" and doc["verdict"] == "BLOCK", (r, doc["verdict"])
    evil = [p for p in doc["packages"] if p["package"] == "evil-native"][0]
    assert evil["via"] == "app → evil-native" and evil["install_script_dependency"], evil
    assert doc["npm_dependency_scripts"]["scanned"] == 3 and doc["npm_dependency_scripts"]["from"] == "registry"

    # a project with a lock: the lock says which dependencies have install scripts (no registry walk)
    Path(d, "package.json").write_text(json.dumps({"dependencies": {"lib": "^2.0.0"}}))
    Path(d, "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "": {}, "node_modules/lib": {"version": "2.0.0"},
        "node_modules/evil-native": {"version": "1.0.3", "hasInstallScript": True}}}))
    npm.metadata = lambda name: (_ for _ in ()).throw(AssertionError("no registry walk with a lock"))
    npm.malicious_releases = lambda pairs: {}
    r = guard_core.check_command("npm install", d)
    doc = json.loads(Path(d, ".aasm", "last_review.json").read_text())
    assert r.action == "refuse" and doc["npm_dependency_scripts"]["from"] == "package-lock.json", doc.get("npm_dependency_scripts")

    # nothing with an install script: nothing more to scan
    Path(d, "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lib": {"version": "2.0.0"}}}))
    assert guard_core.check_command("npm install", d).action == "allow"
print("npm_deps: all cases passed")
