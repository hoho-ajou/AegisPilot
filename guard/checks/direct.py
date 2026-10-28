"""
AegisPilot - check: packages installed from a git repository or a URL (sources/direct.py).

The same code the installer would fetch, scanned with the rules of its ecosystem (scan_engine.scan_direct); one that
cannot be fetched is "not scanned" (a REVIEW that says so, not a registry 404).
"""
from __future__ import annotations

from checks.base import Check, Outcome
from review_report import clean, package_record

DIRECT_MAX_SOURCES = 5           # git / URL sources fetched per command (each is a repository download)


def run(ctx) -> Outcome:
    out = Outcome()
    sources = getattr(ctx.parsed, "direct_sources", [])
    for src in sources[:DIRECT_MAX_SOURCES]:
        try:
            import scan_engine
            from sources import direct
            result = scan_engine.scan_direct(src)
        except Exception as e:
            out.unscanned("vcs_or_url", clean(src.get("url", ""), 200), f"git/URL source not checked: {type(e).__name__}")
            continue
        if not result.features.fetch_ok:          # could not fetch / unpack it: the "not scanned" card, not a registry 404
            out.unscanned("vcs_or_url", clean(direct.shown(src), 200),
                          f"git/URL source not checked, download failed: {clean(result.features.fetch_error or '', 120)}")
            continue
        rec = package_record(result.features.name, result.features.version, result)
        rec["direct_source"] = clean(direct.shown(src), 200)
        if src.get("ecosystem") == "npm":
            rec["ecosystem"] = "npm"
        out.add(rec, ctx.policy(rec, result.features.name, result.features.version, result.verdict))
    for src in sources[DIRECT_MAX_SOURCES:]:
        out.unscanned("too_many_packages", clean(src.get("url", ""), 200), f"not checked: more than {DIRECT_MAX_SOURCES} git/URL sources in one command")
    return out


def on_timeout(ctx) -> Outcome:
    out = Outcome()
    for src in getattr(ctx.parsed, "direct_sources", []):
        out.timed_out(src.get("name") or clean(src.get("url", ""), 80), src.get("ref"), src.get("ecosystem") or "pypi")
    return out


CHECK = Check("direct", lambda p: bool(getattr(p, "direct_sources", None)), run, on_timeout)
