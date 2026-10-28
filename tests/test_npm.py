"""npm packages (2026-10-23): version ranges, command parsing, lifecycle scripts, the npm rules and the guard decision.
Offline: the registry and OSV are replaced by fakes. run: python3 tests/test_npm.py"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
os.environ["AEGIS_ML"] = "0"
from install_parse import parse_install_command  # noqa: E402
from sources import npm  # noqa: E402
import scan_engine as se  # noqa: E402

# ---- version picking: what npm itself would install
vs = ["0.9.0", "1.0.0", "1.2.3", "1.2.10", "1.3.0-beta.1", "1.3.0", "1.9.9", "2.0.0", "2.1.0", "3.0.0-rc.1"]
meta = {"dist-tags": {"latest": "2.1.0", "next": "3.0.0-rc.1"}, "versions": {v: {} for v in vs}}
for spec, want in [("^1.2.3", "1.9.9"), ("~1.2.3", "1.2.10"), ("1.2", "1.2.10"), ("1.x", "1.9.9"), (">=1.2 <2", "1.9.9"),
                   (None, "2.1.0"), ("latest", "2.1.0"), ("next", "3.0.0-rc.1"), ("1.2.3", "1.2.3"), ("^0.9", "0.9.0"),
                   ("1.0.0 - 1.3", "1.3.0"), (">2.1.0", None), ("^1.2.3 || ^2", "2.1.0"), ("not a range!", None)]:
    assert npm.pick_version(meta, spec) == want, (spec, npm.pick_version(meta, spec), want)
assert not npm.satisfies("1.3.0-beta.1", "^1.2.0")          # a range without a prerelease never picks one

# ---- commands
with tempfile.TemporaryDirectory() as d:
    Path(d, "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.0", "x": "github:a/b"},
                                                   "devDependencies": {"jest": "^29"}}))
    Path(d, "package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.21"},
                                                                     "node_modules/jest/node_modules/chalk": {"version": "4.1.2"}}}))

    def eco(c, env=None):
        p = parse_install_command(c, d, env=env or {"HOME": d})
        return p.ecosystem_packages, [u["kind"] for u in p.unscanned], p

    assert eco("npm install lodash@^4 @types/node react@18.2.0")[0] == [("npm", "lodash", "^4"), ("npm", "@types/node", None), ("npm", "react", "18.2.0")]
    pk, un, p = eco("npm ci")
    assert ("npm", "lodash", "4.17.21") in pk and ("npm", "jest", "^29") in pk and un == [], (pk, un)
    assert [s["url"] for s in p.direct_sources] == ["https://github.com/a/b"]      # github:a/b is fetched and scanned
    assert ("chalk", "4.1.2") in p.npm_lock                     # the whole locked tree goes to the malicious-release check
    assert eco("yarn")[0] == pk and eco("pnpm install")[0] == pk
    assert eco("npx -y create-react-app app")[0] == [("npm", "create-react-app", None)]
    assert eco("npx --package=@playwright/mcp playwright-mcp")[0] == [("npm", "@playwright/mcp", None)]
    assert eco("npm init vite@latest my")[0] == [("npm", "create-vite", "latest")]
    assert eco("bunx cowsay hi")[0] == [("npm", "cowsay", None)]
    assert eco("npm install --registry https://npm.corp.example lodash")[1] == ["custom_index"]
    Path(d, ".npmrc").write_text("@corp:registry=https://npm.corp.example\n")
    assert eco("npm install @corp/a left-pad")[0:2] == ([("npm", "left-pad", None)], ["custom_index"])
    assert eco("npm install git+https://github.com/a/b.git")[2].direct_sources[0]["url"] == "https://github.com/a/b.git"
    assert eco("npm install git+ssh://git@github.com/a/b.git")[1] == ["vcs_or_url"]
    assert eco("npm install ./x.tgz")[1] == ["requirements_unreadable"]
    for c in ("npm run build", "npm test", "yarn build", "npm init", "pnpm run dev"):
        assert eco(c)[0:2] == ([], []), c
    Path(d, "node_modules/.bin").mkdir(parents=True)
    Path(d, "node_modules/.bin/tsc").write_text("")
    assert eco("npx tsc")[0] == []                               # the project's own copy runs: nothing is fetched

# ---- lifecycle scripts become files the shell (and, for node -e, JavaScript) rules read
with tempfile.TemporaryDirectory() as d:
    root = Path(d, "x-1.0.0.tgz.unpacked", "package")
    root.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"scripts": {"postinstall": "node -e \"eval(atob('eA=='))\"", "test": "jest"}}))
    out = npm.write_lifecycle(list(Path(d).rglob("*")), Path(d), "x-1.0.0")
    assert sorted(f.name for f in out) == ["package.json#postinstall.js", "package.json#postinstall.sh"], out
    f = se.ScanFeatures(name="x", version="1.0.0", ecosystem="npm")
    v = se.scan_files(list(Path(d).rglob("*")) + out, f)
    assert v.verdict == "BLOCK" and any(e["file"] == "package.json#postinstall.js" for e in f.evidence), f.evidence

# ---- the guard decision with a fake registry scan: BLOCK refuses, ALLOW passes, a malicious lock entry blocks
import guard_core  # noqa: E402


def fake_scan(verdict, rule=None):
    def scan(name, spec=None):
        f = se.ScanFeatures(name=name, version="1.0.0", resolved_version="1.0.0", ecosystem="npm", fetch_ok=True)
        if rule:
            f.evidence = [{"rule": rule, "file": "index.js", "line": 1, "snippet": "eval(atob(x))"}]
        return se.Verdict(verdict, 0.9 if verdict == "BLOCK" else 0.0, [], f)
    return scan


orig_scan, orig_mal, orig_int = se.ECOSYSTEM_SCANNERS["npm"], npm.malicious_releases, guard_core.check_integrity
guard_core.check_integrity = lambda: []          # a dev checkout's manifest is stale; integrity has its own tests
try:
    with tempfile.TemporaryDirectory() as d:
        se.ECOSYSTEM_SCANNERS["npm"] = fake_scan("BLOCK", "decode_then_exec")
        dec = guard_core.check_command("npm install evil-pkg", d)
        assert dec.action in ("refuse", "confirm") and "evil-pkg" in dec.reason, dec
        rec = json.loads(Path(d, ".aegis", "last_review.json").read_text())
        assert any(r.get("ecosystem") == "npm" and r["verdict"] == "BLOCK" for r in rec.get("packages", rec.get("records", []))), rec.keys()
        se.ECOSYSTEM_SCANNERS["npm"] = fake_scan("ALLOW")
        npm.malicious_releases = lambda pairs: {}
        assert guard_core.check_command("npm install left-pad", d).action == "allow"
        Path(d, "package.json").write_text(json.dumps({"dependencies": {"a": "1.0.0"}}))
        Path(d, "package-lock.json").write_text(json.dumps({"packages": {"node_modules/a": {"version": "1.0.0"},
                                                                         "node_modules/a/node_modules/bad": {"version": "6.6.6"}}}))
        npm.malicious_releases = lambda pairs: {("bad", "6.6.6"): ["MAL-2099-1"]} if ("bad", "6.6.6") in pairs else {}
        dec = guard_core.check_command("npm ci", d)
        assert dec.action in ("refuse", "confirm") and "bad" in dec.reason, dec
finally:
    se.ECOSYSTEM_SCANNERS["npm"], npm.malicious_releases, guard_core.check_integrity = orig_scan, orig_mal, orig_int
print("npm: all cases passed")
