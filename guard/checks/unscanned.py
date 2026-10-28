"""
AegisPilot - check: sources the parser already knows it cannot read (install_parse.Parsed.unscanned: an ssh
git URL, an index the person does not use, a requirements file written in the same command ...). Each is a REVIEW that
names what was not checked.
"""
from __future__ import annotations

from checks.base import Check, Outcome
from review_report import unscanned_record


def run(ctx) -> Outcome:
    out = Outcome()
    for item in ctx.parsed.unscanned:
        out.add(unscanned_record(item), "NEEDS_HUMAN_REVIEW")
    return out


CHECK = Check("unscanned", lambda p: bool(p.unscanned), run, run)
