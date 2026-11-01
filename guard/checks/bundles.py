"""
AegisPilot - check: files an agent extension runs - a local MCP server script, a plugin, a hook command or
script. Read with the "bundle" ecosystem (every language is code). A project's own npm install scripts (kind
"project_scripts", npm_parse) are read like an npm package's install scripts (scan_engine.scan_npm_scripts).
"""
from __future__ import annotations

from checks.base import Check, Outcome
from review_report import clean, package_record


def run(ctx) -> Outcome:
    out = Outcome()
    for b in getattr(ctx.parsed, "bundles", []):
        try:
            import scan_engine
            if b.get("kind") == "project_scripts":        # a project's npm install scripts: install-time code
                result = scan_engine.scan_npm_scripts(b.get("name") or b["label"], b.get("texts") or {})
            else:
                result = scan_engine.scan_bundle(b.get("name") or b["label"], b.get("paths", []), b.get("texts"))
        except Exception as e:
            out.unscanned("unparsed", b["label"], f"not checked: {type(e).__name__}")
            continue
        rec = package_record(b.get("name") or b["label"], None, result)      # a short name the cards can show
        rec["bundle"], rec["bundle_label"] = b.get("kind", "bundle"), clean(b["label"], 120)
        if b.get("origin"):
            rec["origin"] = clean(b["origin"], 200)
        out.add(rec, result.verdict)
    return out


def on_timeout(ctx) -> Outcome:
    out = Outcome()
    for b in getattr(ctx.parsed, "bundles", []):
        out.timed_out(b.get("name") or b["label"], None, "bundle")
    return out


CHECK = Check("bundles", lambda p: bool(getattr(p, "bundles", None)), run, on_timeout)
