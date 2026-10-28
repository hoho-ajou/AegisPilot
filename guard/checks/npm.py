"""
AegisPilot - checks that only npm needs:

  lock_malicious   every release in package-lock.json against OSV's malicious-packages records (npm installs, and runs
                   the install scripts of, the whole locked tree)
  script_deps      the dependencies whose install scripts npm will run (package-lock.json's hasInstallScript, or the
                   registry's for a fresh resolve), scanned like named packages and recorded with `via`

The named npm packages themselves are checks/ecosystems.py.
"""
from __future__ import annotations

from checks.base import Check, Outcome, post_rules_into
from review_report import clean, package_record

NPM_TREE_SECONDS = 20            # resolving an npm dependency tree from the registry
NPM_SCRIPT_DEPS_MAX = 15         # dependencies with install scripts scanned per command
NPM_SCRIPT_DEPS_SECONDS = 120


def _lock_malicious(parsed) -> list:
    """[(name, version, Verdict)] for releases in package-lock.json that OSV calls malicious. npm installs (and runs the
    lifecycle scripts of) the whole locked tree, not only the direct dependencies scanned above; one batch query covers
    all of it. The Verdict carries the OSV ids, so the record is built like any other (post rule known_malicious)."""
    if not getattr(parsed, "npm_lock", None):
        return []
    try:
        import scan_engine
        from sources import npm
        found = npm.malicious_releases(parsed.npm_lock)
    except Exception:
        return []
    out = []
    for (name, version), ids in found.items():
        f = scan_engine.ScanFeatures(name=name, version=version, resolved_version=version, ecosystem="npm",
                                     osv_vulns=[{"id": i} for i in ids])
        out.append((name, version, scan_engine.Verdict("ALLOW", 0.0, [], f)))
    return out


def run_lock(ctx) -> Outcome:
    out = Outcome()
    for name, version, result in _lock_malicious(ctx.parsed):       # anywhere in the locked tree (not scanned above)
        rec = package_record(name, version, result)
        rec["ecosystem"], rec["via"] = "npm", "package-lock.json"
        post_rules_into(rec, result, version, True, None, None)
        out.add(rec, ctx.policy(rec, name, version, result.verdict), dependency=True)
    return out


def script_deps(ctx, out: Outcome) -> dict | None:
    """npm runs the install scripts of every package in the tree: the dependencies that have one (package-lock.json's
    hasInstallScript, or the registry's for a fresh resolve - sources/npm.install_script_deps) are scanned like the
    packages the command names; their records carry `via`. Like _check_transitive, never raises and never turns a
    lookup failure into a card: what could not be checked is noted in the record."""
    parsed, osv_ok = ctx.parsed, ctx.osv_ok()
    names = [(n, s) for eco, n, s in getattr(parsed, "ecosystem_packages", []) if eco == "npm"]
    from_lock = getattr(parsed, "npm_lock_scripts", None)
    if not names and not from_lock:
        return None
    try:
        import time as _t
        from concurrent.futures import ThreadPoolExecutor, wait
        import scan_engine
        from sources import npm
        skip = {n for n, _ in names}
        if from_lock is not None:
            found, notes = [d for d in from_lock if d["name"] not in skip], []
        else:
            found, notes = npm.install_script_deps(names, _t.monotonic() + NPM_TREE_SECONDS, skip)
        if len(found) > NPM_SCRIPT_DEPS_MAX:
            notes.append(f"only {NPM_SCRIPT_DEPS_MAX} of {len(found)} dependencies with install scripts checked")
            found = found[:NPM_SCRIPT_DEPS_MAX]
        scanned = 0
        if found:
            ex = ThreadPoolExecutor(min(4, len(found)))
            futures = [ex.submit(scan_engine.scan_npm_package, d["name"], d["version"]) for d in found]
            wait(futures, timeout=NPM_SCRIPT_DEPS_SECONDS)
            ex.shutdown(wait=False, cancel_futures=True)
            for d, fut in zip(found, futures):
                if not fut.done() or fut.exception() is not None or not fut.result().features.fetch_ok:
                    notes.append(f"{d['name']}@{d['version']} not checked")
                    continue
                result = fut.result()
                scanned += 1
                rec = package_record(d["name"], d["version"], result)
                rec["ecosystem"] = "npm"
                rec["via"] = clean(" → ".join(x for x in (d.get("via"), d["name"]) if x), 160)
                rec["install_script_dependency"] = True
                post_rules_into(rec, result, d["version"], osv_ok, None, None)
                out.add(rec, ctx.policy(rec, d["name"], d["version"], rec.get("verdict") or result.verdict), dependency=True)
        return {"with_install_script": len(found), "scanned": scanned, "from": "package-lock.json" if from_lock is not None else "registry",
                "notes": [clean(n, 160) for n in dict.fromkeys(notes)]}
    except Exception as e:
        return {"error": clean(f"{type(e).__name__}: {e}", 160)}


def run_script_deps(ctx) -> Outcome:
    out = Outcome()
    info = script_deps(ctx, out)
    if info:
        out.report["npm_dependency_scripts"] = info
    return out


def _deps_timeout(ctx) -> Outcome:
    """Dependencies are a look further than what the command names: not finishing is noted, not a card."""
    return Outcome(report={"npm_dependency_scripts": {"notes": ["check of dependencies with install scripts did not finish in time"]}})


LOCK_MALICIOUS = Check("npm_lock", lambda p: bool(getattr(p, "npm_lock", None)), run_lock, lambda ctx: Outcome())
SCRIPT_DEPS = Check("npm_script_deps",
                    lambda p: any(e == "npm" for e, _, _ in getattr(p, "ecosystem_packages", []))
                    or getattr(p, "npm_lock_scripts", None) is not None,
                    run_script_deps, _deps_timeout)
