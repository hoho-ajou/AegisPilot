"""The instruction the agent gets is chosen by the rules that held the package (run: python3 tests/test_case_by_rule.py)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
from output import render as R  # noqa: E402


def rec(verdict, rules):
    return {"package": "p", "version": "1", "verdict": verdict, "verdict_rules": rules, "evidence": [{"rule": "keyword"}], "advice": {}}


CASES = [
    ("BLOCK", ["download_exec@import"], "behavior_block", "runs downloaded content when it is imported"),
    ("BLOCK", ["secret_exfil@install"], "behavior_block", "Do not install this version"),
    ("NEEDS_HUMAN_REVIEW", ["install_process@install"], "build", "native build step"),
    ("NEEDS_HUMAN_REVIEW", ["wipe@call"], "call", "only when your code calls that part"),
    ("NEEDS_HUMAN_REVIEW", ["sysinfo_beacon@install"], "behavior_review", "sends system info when it is installed"),
    ("NEEDS_HUMAN_REVIEW", ["not_analyzed@import"], "unread", "retrying gives the same result"),
    ("NEEDS_HUMAN_REVIEW", ["install_process@install", "not_analyzed@import"], "unread", "could not be read"),
    ("NEEDS_HUMAN_REVIEW", ["ml_score"], "ml", "ML model"),
    ("NEEDS_HUMAN_REVIEW", ["install_hook_with_keywords"], "other", "(install_hook_with_keywords)"),
]
for verdict, rules, case, words in CASES:
    r = rec(verdict, rules)
    assert R._advice_case(r) == case, (rules, R._advice_case(r))
    text = R.auto_reason(r)
    assert words in text, (rules, text)
print("case_by_rule: all cases passed")
