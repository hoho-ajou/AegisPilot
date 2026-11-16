"""The agent's message: one instruction per verdict, the rules that held the package by name with what each means, and a
version to use instead when the guard knows one - no message of its own per rule (run: python3 tests/test_case_by_rule.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
from output import render as R  # noqa: E402


def rec(verdict, rules, advice=None):
    return {"package": "p", "version": "1", "verdict": verdict, "verdict_rules": rules, "evidence": [{"rule": "keyword"}], "advice": advice or {}}


CASES = [
    ("BLOCK", ["download_exec@import"], "download_exec@import: runs downloaded content when it is imported"),
    ("BLOCK", ["known_malicious"], "known_malicious: OSV records this release as malicious code"),
    ("BLOCK", ["policy_deny"], "policy_deny: on the deny list of the organization or project"),
    ("NEEDS_HUMAN_REVIEW", ["install_process@install"], "install_process@install: runs an external command when it is installed"),
    ("NEEDS_HUMAN_REVIEW", ["wipe@call"], "wipe@call: deletes the user's or the system's files only when code calls that part"),
    ("NEEDS_HUMAN_REVIEW", ["not_analyzed@import"], "not_analyzed@import:"),
    ("NEEDS_HUMAN_REVIEW", ["ml_score"], "ml_score: the ML model rates it like known malicious packages"),
    ("NEEDS_HUMAN_REVIEW", ["install_hook_with_keywords"], "install_hook_with_keywords: setup.py takes over the install"),
    ("NEEDS_HUMAN_REVIEW", ["osv_unavailable"], "osv_unavailable: the vulnerability DB (OSV) could not be reached (tried 3 times)"),
]
for verdict, rules, words in CASES:
    text = R.auto_reason(rec(verdict, rules))
    assert words in text, (rules, text)
    first, head = text.splitlines()[0], "\n".join(text.splitlines()[:2])
    assert first in ("[AegisPilot] BLOCK — auto mode.", "[AegisPilot] REVIEW — auto mode."), first   # the line the person sees
    if verdict == "BLOCK":
        assert "Do not install this version" in head and "no ack" in head, head
    else:
        assert "Decide from the purpose of the task" in head, head
print("case_by_rule: all cases passed")
