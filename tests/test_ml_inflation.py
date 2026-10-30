"""ML code features (guard/ml/code_features): compression bombs raise ArchiveLimitError quickly, odd gzip input never
loops. Runs in the ML environment (pyzipper); skipped when it is not installed."""
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent / "guard"
sys.path.insert(0, str(HERE))
import ml_bridge

SCRIPT = r"""
import sys, io, gzip, bz2, lzma, tarfile, time
sys.path.insert(0, %r)
import code_features as CF
def tar_of(size, comp):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        ti = tarfile.TarInfo("p/z.dat"); ti.size = size
        class Z(io.RawIOBase):
            left = size
            def readable(s): return True
            def readinto(s, b):
                n = min(len(b), s.left); b[:n] = bytes(n); s.left -= n; return n
        tf.addfile(ti, io.BufferedReader(Z()))
    return comp(raw.getvalue())
def small():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        ti = tarfile.TarInfo("p/a.py"); d = b"x = 1\\n" * 400000; ti.size = len(d); tf.addfile(ti, io.BytesIO(d))
    return raw.getvalue()
def run(data):
    try: return "ok n_py=%%d" %% CF.code_features(data)["n_py"]
    except CF.ArchiveLimitError: return "limit"
MB = 1 << 20
print("gz", run(tar_of(300 * MB, lambda b: gzip.compress(b, 9))))
print("bz2", run(tar_of(300 * MB, bz2.compress)))
print("xz", run(tar_of(300 * MB, lambda b: lzma.compress(b, preset=1))))
print("normal", run(gzip.compress(small())))
print("multi_big", run(gzip.compress(small()) + gzip.compress(b"x" * 1000)))
print("padding", run(gzip.compress(small()) + bytes(512)))
print("garbage", run(b"\x1f\x8b" + b"junk" * 100))
""" % str(HERE / "ml")


@unittest.skipUnless(ml_bridge.ml_python().exists(), "ML environment not installed")
class MLInflation(unittest.TestCase):
    def test_bombs_refused_and_odd_streams_terminate(self):
        p = subprocess.run([str(ml_bridge.ml_python()), "-c", SCRIPT], capture_output=True, text=True, timeout=90)
        got = dict(l.split(" ", 1) for l in p.stdout.splitlines() if " " in l)
        self.assertEqual(got.get("gz"), "limit", p.stderr[-300:])
        self.assertEqual(got.get("bz2"), "limit")
        self.assertEqual(got.get("xz"), "limit")
        for k in ("normal", "multi_big", "padding", "garbage"):
            self.assertTrue(got.get(k, "").startswith("ok"), (k, got))


if __name__ == "__main__":
    unittest.main()
