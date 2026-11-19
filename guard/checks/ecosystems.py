"""
AegisPilot - check: packages from registries other than PyPI (scan_engine.ECOSYSTEM_SCANNERS: npm today),
scanned in parallel under one time budget; a package not finished in time (or past the count limit) is a REVIEW that
says so, never dropped.
"""
from __future__ import annotations

from checks.base import Check, Outcome, check_replacements, internal_package, post_rules_into
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


DEPS_WAIT_SECONDS = 190          # the dependency stage: tree (20 s) + OSV batch + publish times (15 s) + scans (120 s)


def _npm_wanted(parsed) -> bool:
    return any(e == "npm" for e, _, _ in getattr(parsed, "ecosystem_packages", [])) or \
        getattr(parsed, "npm_lock_scripts", None) is not None


def run(ctx) -> Outcome:
    """The same stages as the PyPI check (checks/pypi.py), in the same order:
      1 the version each spec installs (sources/npm.pick_version, inside the scan)
      3 each package scanned (scan_engine._scan_release: download -> rules -> behavior | OSV | dependency list | ML)
      4 post rules   5 allow / deny lists
      7 dependencies: the tree npm installs -> OSV batch -> the risky ones scanned like 3 (checks/npm.script_deps).
        npm knows the tree before the scans finish (lock file or registry), so this stage starts with 3 and is joined
        here; PyPI needs the scanned packages' dependency lists first, so its stage 7 starts after 3.
    PyPI-only: 2 the verdict cache and 6 the nearest version (a spec npm cannot match is a REVIEW that says so)."""
    import threading
    import time
    out = Outcome()
    ctx.start_osv()
    deps_out, deps_box, th = Outcome(), {}, None
    if _npm_wanted(ctx.parsed):
        from checks import npm as npm_check

        def deps():
            deps_box["info"] = npm_check.script_deps(ctx, deps_out)
        th = threading.Thread(target=deps, daemon=True)
        th.start()
    started = time.monotonic()
    results = _scan(ctx.parsed)
    osv_ok = ctx.osv_ok()
    for eco, name, version, result in results:
        rec = package_record(name, result.features.version or version, result)
        rec["ecosystem"] = eco
        post_rules_into(rec, result, result.features.version, osv_ok, None, None)
        verdict = "ALLOW" if internal_package(rec, result, ctx.parsed) else result.verdict
        out.add(rec, ctx.policy(rec, name, result.features.version, verdict))
    if th is not None:
        th.join(max(0.0, DEPS_WAIT_SECONDS - (time.monotonic() - started)))
        if th.is_alive():
            out.report["npm_dependency_scripts"] = {"notes": ["check of dependencies with install scripts did not finish in time"]}
        else:
            out.dependencies.extend(deps_out.dependencies)
            if deps_box.get("info"):
                out.report["npm_dependency_scripts"] = deps_box["info"]
    check_replacements(ctx, out, osv_ok)                # the version named instead of each held one, scanned now
    return out


def on_timeout(ctx) -> Outcome:
    out = Outcome(report={"npm_dependency_scripts": {"notes": ["check of dependencies with install scripts did not finish in time"]}}
                  if _npm_wanted(ctx.parsed) else {})
    for eco, name, spec in ctx.parsed.ecosystem_packages:
        out.timed_out(name, spec, eco)
    return out


CHECK = Check("ecosystems", lambda p: bool(getattr(p, "ecosystem_packages", None)) or _npm_wanted(p), run, on_timeout)
