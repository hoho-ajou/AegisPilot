"""A package archive must never make the scanner write outside its extraction directory."""
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "guard"))
import scan_engine as E
from sources import pypi


class _Resp(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *a): return False


def fetch(filename, data, dest):
    meta = {"info": {"version": "1.0"}, "releases": {"1.0": [{"filename": filename, "packagetype": "sdist", "size": len(data), "url": "https://files.pythonhosted.org/x/" + filename}]}}
    with mock.patch.object(pypi, "metadata", lambda n: meta), mock.patch.object(pypi.urllib.request, "urlopen", lambda *a, **k: _Resp(data)):
        return pypi.fetch("x", "1.0", dest)


def tar_bytes(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


class ExtractSafety(unittest.TestCase):
    def test_symlink_member_cannot_redirect_a_later_write(self):
        with tempfile.TemporaryDirectory() as d:
            outside = Path(d) / "outside"; outside.mkdir()
            ln = tarfile.TarInfo("p/link"); ln.type = tarfile.SYMTYPE; ln.linkname = str(outside)
            payload = b"x"; f = tarfile.TarInfo("p/link/pwned.txt"); f.size = 1
            dest = Path(d) / "dest"; dest.mkdir()
            fetch("x-1.0.tar.gz", tar_bytes([(ln, None), (f, payload)]), dest)       # must not raise: the safe members extract fine
            self.assertFalse((outside / "pwned.txt").exists())

    def test_hardlink_member_cannot_overwrite_an_existing_file(self):
        with tempfile.TemporaryDirectory() as d:
            victim = Path(d) / "victim.txt"; victim.write_text("ORIGINAL")
            ln = tarfile.TarInfo("p/hl"); ln.type = tarfile.LNKTYPE; ln.linkname = str(victim)
            f = tarfile.TarInfo("p/hl"); f.size = 5
            dest = Path(d) / "dest"; dest.mkdir()
            fetch("x-1.0.tar.gz", tar_bytes([(ln, None), (f, b"EVIL!")]), dest)
            self.assertEqual(victim.read_text(), "ORIGINAL")

    def test_regular_files_still_extracted(self):
        with tempfile.TemporaryDirectory() as d:
            f = tarfile.TarInfo("p/setup.py"); f.size = 9
            _, files = fetch("x-1.0.tar.gz", tar_bytes([(f, b"print(1)\n")]), Path(d))
            self.assertTrue(any(p.name == "setup.py" for p in files))

    def test_registry_file_name_cannot_point_outside_dest(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / "dest"; dest.mkdir()
            f = tarfile.TarInfo("p/setup.py"); f.size = 9
            data = tar_bytes([(f, b"print(1)\n")])
            fetch("../../esc_rel.tar.gz", data, dest)
            fetch(str(Path(d) / "esc_abs.tar.gz"), data, dest)
            self.assertEqual([p.name for p in Path(d).iterdir()], ["dest"])           # nothing created beside dest
            self.assertTrue((dest / "esc_rel.tar.gz").exists() and (dest / "esc_abs.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
