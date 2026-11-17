"""A version that is not on PyPI: the guard names the nearest one that is, checked (run: python3 tests/test_nearest_version.py)."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import scan_engine as se  # noqa: E402
from output import render  # noqa: E402
from output import text_format  # noqa: E402

NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)


def rel(hours_ago, yanked=False):
    return [{"upload_time_iso_8601": (NOW - timedelta(hours=hours_ago)).isoformat(), "yanked": yanked}]


META = {"releases": {"1.0": rel(900), "2.32.4": rel(500), "2.32.5": rel(400), "2.33.0": rel(300, yanked=True),
                     "2.34.0rc1": rel(200), "2.34.1": rel(100), "2.34.2": rel(3), "3.0.0": []}}
near = se.pypi_nearest_version
assert near(META, "2.32.6", 24, NOW) == "2.32.5"            # the highest release below
assert near(META, "2.99.0", 24, NOW) == "2.34.1"            # 2.34.2 is under a day old, 2.34.0rc1 a pre-release
assert near(META, "2.33.0", 24, NOW) == "2.32.5"            # a yanked version is not offered
assert near(META, "0.1", 24, NOW) == "1.0"                  # nothing below: the lowest above
assert near(META, "2.34.0rc2", 24, NOW) == "2.34.0rc1"      # a pre-release asked for: pre-releases count
assert near({"releases": {}}, "1.0", 24, NOW) is None

rec = {"package": "requests", "version": "2.99.0", "verdict": "NEEDS_HUMAN_REVIEW", "evidence": [{"rule": "fetch_error"}],
       "coverage": {"analyzed": False, "failure_kind": "version_missing"},
       "advice": {"failure_kind": "version_missing", "nearest_version": "2.34.1", "nearest_verdict": "ALLOW", "nearest_rules": []}}
t = render.auto_reason(rec)
assert "suggested: requests==2.34.1 (the nearest version that exists, checked: passed)" in t, t
assert "Nearest on PyPI: 2.34.1 (checked: passed)" in text_format.popup_line(rec), text_format.popup_line(rec)
held = {**rec, "advice": {**rec["advice"], "nearest_verdict": "NEEDS_HUMAN_REVIEW", "nearest_rules": ["known_vulnerability"]}}
assert "checked: held too" in render.auto_reason(held)
assert "checked: held" in text_format.popup_line(held)
print("nearest_version: all cases passed")
