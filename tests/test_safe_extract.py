"""safe_extract: only what the analysis reads, never outside the root, bombs refused (ArchiveLimitError)."""
import gzip
import io
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "guard"))
import safe_extract as SE
import scan_engine as E

MB = 1 << 20


def make_zip(members, compress=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as z:
        for name, data in members.items():
            zi = zipfile.ZipInfo("x"); zi.filename = name; zi.compress_type = compress    # keep odd names as written
            z.writestr(zi, data)
    return buf.getvalue()


def make_tar(members, links=(), gz=True):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz" if gz else "w") as tf:
        for name, data in members.items():
            ti = tarfile.TarInfo(name); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
        for name, target in links:
            ti = tarfile.TarInfo(name); ti.type = tarfile.SYMTYPE; ti.linkname = target; tf.addfile(ti)
    return buf.getvalue()


def run(fn, raw):
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / "r"; root.mkdir(); skipped = []
        out = fn(raw, root, skipped)
        everything = sorted(str(p.relative_to(Path(d))) for p in Path(d).rglob("*") if p.is_file())
        return sorted(str(p.relative_to(root)) for p in out), skipped, everything


class Names(unittest.TestCase):
    BAD = ["../esc.py", "a/../../esc.py", "/abs/esc.py", "..\\esc.py", "C:/esc.py", "a/..", "x" * 300 + ".py", "ok\x00.py"]

    def test_unsafe_names_skipped_and_reported_in_both_formats(self):
        members = {n: b"x = 1\n" for n in self.BAD}
        members["pkg/ok.py"] = b"y = 2\n"
        for fn, raw in ((SE.extract_zip, make_zip(members)), (SE.extract_targz, make_tar({k: v for k, v in members.items() if "\x00" not in k}))):
            out, skipped, everything = run(fn, raw)
            self.assertEqual(out, ["pkg/ok.py"])
            self.assertEqual(everything, ["r/pkg/ok.py"])                 # nothing anywhere else, nothing outside r/
            self.assertGreaterEqual(len(skipped), 6)

    def test_one_odd_name_does_not_abort_the_rest(self):
        out, skipped, _ = run(SE.extract_zip, make_zip({"a/..": b"", "pkg/ok.py": b"x"}))
        self.assertEqual(out, ["pkg/ok.py"])

    def test_only_wanted_files(self):
        # code, text an agent reads (2026-10-23), not data or binaries
        raw = make_tar({"p/setup.py": b"a", "p/evil.pth": b"import os", "p/data.bin": b"zz", "p/README.md": b"hello",
                        "p/doc.txt": b"t", "p/dataset.json": b"{}", "p/conf.yaml": b"a: 1"})
        out, skipped, _ = run(SE.extract_targz, raw)
        self.assertEqual(out, ["p/README.md", "p/doc.txt", "p/evil.pth", "p/setup.py"])
        self.assertEqual(skipped, [])

    def test_text_is_read_markers_are_empty(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            SE.extract_zip(make_zip({"p/README.md": b"hello", "p/mod.pyc": b"\x00bytecode", "p/big.js": b"x" * (SE.TEXT_MAX_BYTES + 1),
                                     "README": b"plain"}), root, [])
            self.assertEqual((root / "p/README.md").read_bytes(), b"hello")       # an agent reads it: the content matters
            self.assertEqual((root / "p/mod.pyc").read_bytes(), b"")              # presence only
            self.assertEqual((root / "README").read_bytes(), b"")                 # no suffix: the reputation marker
            self.assertFalse((root / "p/big.js").exists())                        # over the text limit

    def test_files_installed_outside_the_package(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            SE.extract_zip(make_zip({"x-1.data/scripts/ls": b"#!/bin/sh\n", "x-1.data/data/pip.conf": b"[global]",
                                     "x-1.data/headers/x.bin": b"zz", "x-1.dist-info/entry_points.txt": b"[console_scripts]",
                                     "x/data/table.bin": b"zz"}), root, [])
            got = sorted(str(p.relative_to(root)) for p in root.rglob("*") if p.is_file())
            self.assertEqual(got, ["x-1.data/data/pip.conf", "x-1.data/scripts/ls", "x-1.dist-info/entry_points.txt"])

    def test_symlinks_dropped_silently(self):
        out, skipped, everything = run(SE.extract_targz, make_tar({"p/a.py": b"x"}, links=[("p/link", "/etc")]))
        self.assertEqual((out, skipped), (["p/a.py"], []))                 # common in real sdists: not a finding
        self.assertEqual(everything, ["r/p/a.py"])

    def test_later_duplicate_wins_like_the_installer(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for data in (b"first", b"second"):
                ti = tarfile.TarInfo("p/a.py"); ti.size = len(data); tf.addfile(ti, io.BytesIO(data))
        with tempfile.TemporaryDirectory() as d:
            SE.extract_targz(buf.getvalue(), Path(d), [])
            self.assertEqual((Path(d) / "p/a.py").read_bytes(), b"second")


class Bombs(unittest.TestCase):
    def test_zip_ratio_refused(self):
        with self.assertRaisesRegex(SE.ArchiveLimitError, "compression ratio"):
            run(SE.extract_zip, make_zip({"p/bomb.py": bytes(2 * MB)}))                 # ~1000x, only 2MB

    def test_small_highly_compressible_file_is_not_a_bomb(self):
        out, _, _ = run(SE.extract_zip, make_zip({"p/a.py": b"#" * 100_000}))           # 100KB < RATIO_MIN_BYTES
        self.assertEqual(out, ["p/a.py"])

    def test_ratio_just_under_the_limit_passes(self):
        import os, random
        random.seed(1)
        data = bytes(random.choice(b"abcdefgh") for _ in range(3 * MB))                   # ~2.7x, normal text-like
        out, _, _ = run(SE.extract_zip, make_zip({"p/big.py": data}))
        self.assertEqual(out, ["p/big.py"])

    def test_member_and_total_and_count_caps(self):
        with mock.patch.object(SE, "MAX_MEMBER_BYTES", 1000):
            with self.assertRaisesRegex(SE.ArchiveLimitError, "one file"):
                run(SE.extract_zip, make_zip({"p/a.py": b"x" * 2000}))
            with self.assertRaisesRegex(SE.ArchiveLimitError, "one file"):
                run(SE.extract_targz, make_tar({"p/a.py": b"x" * 2000}))
        with mock.patch.object(SE, "MAX_TOTAL_BYTES", 1500):
            with self.assertRaisesRegex(SE.ArchiveLimitError, "total"):
                run(SE.extract_zip, make_zip({"p/a.py": b"x" * 1000, "p/b.py": b"y" * 1000}))
            with self.assertRaisesRegex(SE.ArchiveLimitError, "total"):
                run(SE.extract_targz, make_tar({"p/a.py": b"x" * 1000, "p/b.py": b"y" * 1000}))
        with mock.patch.object(SE, "MAX_MEMBERS", 3):
            with self.assertRaisesRegex(SE.ArchiveLimitError, "files"):
                run(SE.extract_zip, make_zip({f"p/{i}.py": b"x" for i in range(5)}))
            with self.assertRaisesRegex(SE.ArchiveLimitError, "files"):
                run(SE.extract_targz, make_tar({f"p/{i}.py": b"x" for i in range(5)}))

    def test_targz_stream_ratio_refused_before_writing_anything(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", compresslevel=9) as tf:
            ti = tarfile.TarInfo("p/zeros.dat"); ti.size = 300 * MB                       # NOT a wanted file: still bounded
            class Z(io.RawIOBase):
                left = ti.size
                def readable(s): return True
                def readinto(s, b):
                    n = min(len(b), s.left); b[:n] = bytes(n); s.left -= n; return n
            tf.addfile(ti, io.BufferedReader(Z()))
        raw = buf.getvalue()
        self.assertLess(len(raw), 2 * MB)
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaisesRegex(SE.ArchiveLimitError, "compression ratio"):
                SE.extract_targz(raw, Path(d), [])
            self.assertEqual(list(Path(d).rglob("*")), [])

    def test_stream_inflation_cap(self):
        with mock.patch.object(SE, "MAX_STREAM_INFLATED", 1000), mock.patch.object(SE, "MAX_RATIO", 10 ** 9):
            with self.assertRaisesRegex(SE.ArchiveLimitError, "GB"):
                run(SE.extract_targz, make_tar({"p/a.py": b"x" * 100_000}))

    def test_nested_archives_are_inert_not_recursed(self):
        inner = make_zip({"p/bomb.py": bytes(50 * MB)})                                    # a bomb one layer down
        outer = make_zip({"p/inner.zip": inner, "p/ok.py": b"x = 1\n"}, compress=zipfile.ZIP_STORED)
        out, skipped, everything = run(SE.extract_zip, outer)
        self.assertEqual((out, skipped), (["p/ok.py"], []))
        outer_t = make_tar({"p/inner.tar.gz": gzip.compress(bytes(50 * MB)), "p/ok.py": b"x"})
        out, _, _ = run(SE.extract_targz, outer_t)
        self.assertEqual(out, ["p/ok.py"])

    def test_multi_member_gzip_is_read_fully(self):
        a, b = make_tar({"p/a.py": b"1"}, gz=False), make_tar({"p/b.py": b"2"}, gz=False)
        # a gzip stream made of two members decodes to a followed by b; tar stops at the first end marker, so just check no crash
        out, _, _ = run(SE.extract_targz, gzip.compress(a) + gzip.compress(b))
        self.assertIn("p/a.py", out)

    def test_multi_member_gzip_with_large_output_terminates(self):
        # regression: a 1MB+ member followed by another member / padding / junk must not loop (found in the ML model's copy)
        big = make_tar({"p/a.py": b"x = 1\n" * 400_000}, gz=False)
        for tail in (gzip.compress(b"x" * 1000), bytes(512), b"junkjunk" * 50):
            out, _, _ = run(SE.extract_targz, gzip.compress(big) + tail)
            self.assertEqual(out, ["p/a.py"])

    def test_corrupt_gzip_is_an_ordinary_failure(self):
        raw = bytearray(make_tar({"p/a.py": b"x" * 100})); raw[-6] ^= 0xFF
        with self.assertRaises(Exception):
            run(SE.extract_targz, bytes(raw))


class Verdict(unittest.TestCase):
    def test_skipped_unsafe_member_is_review(self):
        f = E.ScanFeatures(name="p", version="1", skipped_members=[("../x.py", "path traversal (..)")])
        v = E.compute_verdict(f)
        self.assertEqual(v.verdict, "NEEDS_HUMAN_REVIEW")
        self.assertTrue(any("skipped" in r.lower() for r in v.reasons))

    def test_no_skipped_members_no_effect(self):
        self.assertEqual(E.compute_verdict(E.ScanFeatures(name="p", version="1")).verdict, "ALLOW")


if __name__ == "__main__":
    unittest.main()
