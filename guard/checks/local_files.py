"""
AegisPilot - check: wheels / sdists already on disk (`pip install ./x.whl`).

Their code, read like a PyPI release (scan_engine.scan_local_file) but without the checks about a PyPI project of that
name (it is not what is installed).
"""
from __future__ import annotations

from checks.base import Check, Outcome
from review_report import clean, package_record


def run(ctx) -> Outcome:
    out = Outcome()
    for shown, path in ctx.parsed.local_files:
        try:
            import scan_engine
            result = scan_engine.scan_local_file(path)
        except Exception as e:
            out.unscanned("requirements_unreadable", shown, f"local package file not checked: {type(e).__name__}")
            continue
        name, version = result.features.name, result.features.version
        rec = package_record(name, version, result)
        rec["local_file"] = clean(shown, 200)
        out.add(rec, ctx.policy(rec, name, version, result.verdict))
    return out


def on_timeout(ctx) -> Outcome:
    out = Outcome()
    for shown, _ in ctx.parsed.local_files:
        out.timed_out(shown, None)
    return out


CHECK = Check("local_files", lambda p: bool(p.local_files), run, on_timeout)
