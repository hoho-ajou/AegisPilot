"""Process-based scanning of several packages (run: python3 tests/test_scan_parallel.py). Needs network (PyPI, OSV)."""
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
os.environ["AEGIS_ML"] = "0"
import scan_engine  # noqa: E402
import scan_parallel as SP  # noqa: E402

items = [("six", "1.16.0"), ("idna", "2.8"), ("certifi", "2020.6.20"), ("pyyaml", "5.3.1")]
assert SP._use_processes(items) and not SP._use_processes(items[:2])
os.environ["AEGIS_SCAN_PROCESSES"] = "0"; assert not SP._use_processes(items); del os.environ["AEGIS_SCAN_PROCESSES"]
os.environ["AEGIS_ML"] = "1"; assert not SP._use_processes(items); os.environ["AEGIS_ML"] = "0"     # ML on: threads

by_threads = [v.verdict for v in scan_engine.scan_packages(items)]
by_procs = [v.verdict for v in SP.scan_packages(items)]
assert by_procs == by_threads and by_procs[3] == "BLOCK", (by_procs, by_threads)        # same verdicts, same order

t = time.time()
cut = SP.scan_packages(items, budget=0.05)
assert time.time() - t < 10 and all(v.verdict == "NEEDS_HUMAN_REVIEW" and "timed out" in v.reasons[0] for v in cut), [v.reasons for v in cut]

# a replaced scan_packages (tests, patches) is used as is
orig = scan_engine.scan_packages
scan_engine.scan_packages = lambda items, **k: ["patched"] * len(items)
try:
    assert SP.scan_packages(items) == ["patched"] * 4
finally:
    scan_engine.scan_packages = orig
print("scan_parallel: all cases passed")
