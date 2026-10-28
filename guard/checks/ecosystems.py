"""
AegisPilot - check: packages from registries other than PyPI (scan_engine.ECOSYSTEM_SCANNERS: npm today),
scanned in parallel under one time budget; a package not finished in time (or past the count limit) is a REVIEW that
says so, never dropped.
"""
from __future__ import annotations

from checks.base import Check, Outcome, internal_package, post_rules_into
from review_report import package_record

ECOSYSTEM_MAX_PACKAGES = 40      # packages scanned per command (a package.json can list many more)
ECOSYSTEM_BUDGET_SECONDS = 300


def _scan(parsed) -> list:
    """[(ecosystem, name, spec, Verdict)] for Parsed.ecosystem_packages, scanned in parallel under one time budget; a
    package not finished in time (or past the count limit) is a REVIEW that says so, never dropped."""
    items = list(getattr(parsed, "ecosystem_packages", []))
    if not items:
        return []
    import scan_engine
    from concurrent.futures import ThreadPoolExecutor, wait
    out, todo = [], items[:ECOSYSTEM_MAX_PACKAGES]
    ex = ThreadPoolExecutor(min(4, len(todo)))
    futures = [ex.submit(scan_engine.ECOSYSTEM_SCANNERS[eco], name, spec) for eco, name, spec in todo]
    wait(futures, timeout=ECOSYSTEM_BUDGET_SECONDS)
    ex.shutdown(wait=False, cancel_futures=True)

    def unscanned(eco, name, spec, why):
        f = scan_engine.ScanFeatures(name=name, version=spec, ecosystem=eco, fetch_error=why)
        return eco, name, spec, scan_engine.Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {why}"], f)
    for (eco, name, spec), fut in zip(todo, futures):
        if fut.done() and fut.exception() is None:
            out.append((eco, name, spec, fut.result()))
        else:
            out.append(unscanned(eco, name, spec, "not checked: timed out" if not fut.done() else f"check failed: {type(fut.exception()).__name__}"))
    out += [unscanned(eco, name, spec, "not checked: too many packages in one command") for eco, name, spec in items[ECOSYSTEM_MAX_PACKAGES:]]
    return out


def run(ctx) -> Outcome:
    out = Outcome()
    ctx.start_osv()
    results = _scan(ctx.parsed)
    osv_ok = ctx.osv_ok()
    for eco, name, version, result in results:
        rec = package_record(name, result.features.version or version, result)
        rec["ecosystem"] = eco
        post_rules_into(rec, result, result.features.version, osv_ok, None, None)
        verdict = "ALLOW" if internal_package(rec, result, ctx.parsed) else result.verdict
        out.add(rec, ctx.policy(rec, name, result.features.version, verdict))
    return out


def on_timeout(ctx) -> Outcome:
    out = Outcome()
    for eco, name, spec in ctx.parsed.ecosystem_packages:
        out.timed_out(name, spec, eco)
    return out


CHECK = Check("ecosystems", lambda p: bool(getattr(p, "ecosystem_packages", None)), run, on_timeout)
