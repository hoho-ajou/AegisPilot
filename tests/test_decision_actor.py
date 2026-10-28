"""Parallel agents in one project: each decision names its id and its session, and "why?" finds the caller's own
decision first (run: python3 tests/test_decision_actor.py). Offline."""
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
from guard_core import _with_decision_id          # noqa: E402
from review_report import load_review, write_report   # noqa: E402

# the message names the decision once
assert _with_decision_id("blocked", {"decision_id": "D1a2b"}).endswith("(decision id: D1a2b)")
assert _with_decision_id("blocked D1a2b", {"decision_id": "D1a2b"}) == "blocked D1a2b"
assert _with_decision_id("blocked", {}) == "blocked"

proj = tempfile.mkdtemp()
a = {"kind": "install", "command": "pip install a", "packages": [], "actor": {"session_id": "S-A", "agent_id": "x1"}}
write_report(proj, a)
time.sleep(0.05)
b = {"kind": "install", "command": "pip install b", "packages": [], "actor": {"session_id": "S-B"}}
write_report(proj, b)

# without a session the latest decision is returned (old behaviour); with one, that session's latest
os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
assert load_review(proj)["command"] == "pip install b"
os.environ["CLAUDE_CODE_SESSION_ID"] = "S-A"
assert load_review(proj)["command"] == "pip install a"
assert load_review(proj, b["decision_id"])["command"] == "pip install b"       # an explicit id always wins
os.environ["CLAUDE_CODE_SESSION_ID"] = "S-none"
assert load_review(proj)["command"] == "pip install b"                         # no decision of its own: latest

print("decision_actor: all cases passed")
