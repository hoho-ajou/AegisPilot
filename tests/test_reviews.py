"""Decision ids and per-decision records (run: python3 tests/test_reviews.py).

Before, one shared .aasm/last_review.json was overwritten by parallel agents, so "why?" could show
another decision. Each decision now has its own file; last_review.json stays as the latest copy."""
import json
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import review_report as R  # noqa: E402

with tempfile.TemporaryDirectory() as t:
    proj = Path(t)
    docs = [{"kind": "install", "command": f"pip install p{i}", "packages": [{"package": f"p{i}"}, {"package": f"q{i}"}]} for i in range(40)]
    threads = [threading.Thread(target=R.write_report, args=(proj, d)) for d in docs]
    [th.start() for th in threads]
    [th.join() for th in threads]
    ids = [d["decision_id"] for d in docs]
    assert len(set(ids)) == 40 and all(i.startswith("D") for i in ids)              # every decision its own id
    for d in docs:                                                                     # its own file, its own content
        saved = R.load_review(proj, d["decision_id"])
        assert saved["command"] == d["command"] and [p["pid"] for p in saved["packages"]] == ["P01", "P02"]
    latest = R.load_review(proj)
    assert latest["decision_id"] in ids and latest == R.load_review(proj, latest["decision_id"])   # last_review = a complete copy
    assert not list((proj / ".aasm").glob(".*.tmp")) and not list((proj / ".aasm/reviews").glob(".*.tmp"))
    assert R.load_review(proj, "../../etc/passwd") is None and R.load_review(proj, "Dzzzz") is None   # ids are validated
    # old decisions are trimmed
    R.MAX_REVIEWS_KEPT = 10
    R.write_report(proj, {"kind": "install", "packages": []})
    assert len(list((proj / ".aasm/reviews").glob("D*.json"))) == 10

print("reviews: all cases passed")
