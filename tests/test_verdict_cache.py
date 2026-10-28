"""Opt-in verdict cache (run: python3 tests/test_verdict_cache.py). Offline: the scan is a fake."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import scan_engine as se  # noqa: E402
import verdict_cache as VC  # noqa: E402

calls = []


def fake_scan(items):
    calls.append(list(items))
    return [se.Verdict("BLOCK" if n == "bad" else "ALLOW", 0.1, ["t"], se.ScanFeatures(name=n, version=v, fetch_ok=True,
            fetch_error="network" if n == "flaky" else None)) for n, v in items]


with tempfile.TemporaryDirectory() as d:
    items = [("bad", "1.0"), ("good", "2.0"), ("latest", None), ("flaky", "1.0")]
    first = VC.scan_with_cache(d, items, fake_scan)
    again = VC.scan_with_cache(d, items, fake_scan)
    assert [v.verdict for v in again] == [v.verdict for v in first] == ["BLOCK", "ALLOW", "ALLOW", "ALLOW"]
    assert calls[1] == [("latest", None), ("flaky", "1.0")]          # unpinned and failed scans are never reused
    doc = json.loads((Path(d) / ".aasm/cache/verdicts.json").read_text())
    assert set(doc) == {"bad==1.0", "good==2.0"}
    for e in doc.values():                                           # expired entries are rescanned
        e["t"] = time.time() - VC.TTL_SECONDS - 1
    (Path(d) / ".aasm/cache/verdicts.json").write_text(json.dumps(doc))
    VC.scan_with_cache(d, items[:2], fake_scan)
    assert calls[2] == items[:2]
    doc = json.loads((Path(d) / ".aasm/cache/verdicts.json").read_text())
    for e in doc.values():                                           # made under other rules (an update, a rule module)
        e["r"] = "other-rules"
    (Path(d) / ".aasm/cache/verdicts.json").write_text(json.dumps(doc))
    VC.scan_with_cache(d, items[:2], fake_scan)
    assert calls[3] == items[:2]
    (Path(d) / ".aasm/cache/verdicts.json").write_text("{broken")     # a damaged file is a miss, never a crash
    assert len(VC.scan_with_cache(d, items[:1], fake_scan)) == 1
    assert not VC.enabled()                                          # off unless AASM_CACHE=1
print("verdict_cache: all cases passed")
