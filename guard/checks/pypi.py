"""
AegisPilot - check: packages from PyPI.

The packages the command names: scanned (scan_engine.scan_package via the context's scanner, the verdict cache when on),
each compared with its previous release beside the scan (version_diff: new risky code, a file added to an old release),
the post rules and the allow / deny lists. Then their dependencies: OSV-malicious and recent releases scanned like the
named ones (transitive.py), recorded with `via`.
"""
from __future__ import annotations

import threading
import time

from checks.base import POST_LABELS, Check, Outcome, internal_package, post_rules_into
from review_report import clean, package_record

VDIFF_MAX_PACKAGES = 20     # look-backs started per command (each downloads the release, and the previous one if needed)
VDIFF_WAIT_SECONDS = 30     # waited after the scan at most


def _look_back(packages) -> tuple[dict, dict, dict, list]:
    """version_diff for each package, in the background: (vdiff, late, features-for-ML, threads)."""
    vdiff_box, late_box, vfeat_box, threads = {}, {}, {}, []
    try:
        from version_diff import check as vdiff_check
        from version_diff import late_file

        def one(name, version):
            try:
                from sources import pypi
                meta = pypi.metadata(name)
            except Exception:
                return
            try:
                late_box[(name, version)] = late_file(meta, version)       # a file added to an old release
            except Exception:
                pass
            try:
                feats: dict = {}
                vdiff_box[(name, version)] = vdiff_check(name, version, meta, features_out=feats)
                if feats:
                    vfeat_box[(name, version)] = feats
            except Exception:
                vdiff_box[(name, version)] = None
        for name, version in packages[:VDIFF_MAX_PACKAGES]:
            th = threading.Thread(target=one, args=(name, version), daemon=True)
            th.start()
            threads.append(th)
    except Exception:
        threads = []
    return vdiff_box, late_box, vfeat_box, threads


def run(ctx) -> Outcome:
    parsed, out = ctx.parsed, Outcome()
    ctx.start_osv()                                     # beside the scan, waited for after it
    vdiff_box, late_box, vfeat_box, threads = _look_back(parsed.packages)
    try:
        import verdict_cache
        use_cache = verdict_cache.enabled()
    except Exception:
        use_cache = False
    results = (verdict_cache.scan_with_cache(ctx.project_dir, parsed.packages, ctx.scan_packages) if use_cache
               else ctx.scan_packages(parsed.packages))
    osv_ok = ctx.osv_ok()
    if not osv_ok and use_cache:
        verdict_cache.forget(ctx.project_dir, parsed.packages)
    wait_until = time.monotonic() + VDIFF_WAIT_SECONDS     # after the scan; a slow look-back is skipped, never waited on
    for th in threads:
        th.join(max(0.0, wait_until - time.monotonic()))
    for (name, version), result in zip(parsed.packages, results):
        rec = package_record(name, version, result)
        post_rules_into(rec, result, version, osv_ok, vdiff_box.get((name, version)), late_box.get((name, version)))
        if vfeat_box.get((name, version)):
            rec["version_diff_features"] = vfeat_box[(name, version)]
        if getattr(parsed, "project_installs", None):
            rec["project_install"] = True          # the card then explains the project file formats and lock refresh
        out.add(rec, ctx.policy(rec, name, version, "ALLOW" if internal_package(rec, result, parsed) else result.verdict))
    info = transitive(parsed, results, osv_ok, out)
    if info:
        out.report["transitive"] = info
    return out


def on_timeout(ctx) -> Outcome:
    out = Outcome()
    for name, version in ctx.parsed.packages:
        out.timed_out(name, version)
    return out


def transitive(parsed, results, osv_ok: bool, out: Outcome) -> dict | None:
    """Dependencies of the packages this command installs (transitive.py): OSV-malicious releases and recent releases
    are scanned like direct packages; their records carry `via` (which direct package pulls them in). Never raises:
    a failure here is recorded and the direct packages' decision stands."""
    try:
        import time as _t
        import scan_engine
        import transitive
        cfg = transitive.settings()
        deadline = _t.monotonic() + cfg["budget_seconds"]
        direct = [{"name": n, "version": r.features.resolved_version or v, "dependencies": r.features.dependencies}
                  for (n, v), r in zip(parsed.packages, results) if getattr(r.features, "dependencies", None)]
        if not direct:
            return None
        from sources import pypi
        found, notes = transitive.walk(direct, pypi.metadata, parsed.lock_pins, deadline=deadline)
        malicious = {}
        if osv_ok and found:
            try:
                malicious = transitive.osv_malicious(found)
            except Exception as e:
                notes.append(f"OSV batch lookup of transitive dependencies failed: {type(e).__name__}")
        todo = [r for r in found if (r["name"], r.get("version")) in malicious]
        recent = [r for r in found if r.get("recent") and r not in todo]
        if len(recent) > cfg["max_scans"]:
            notes.append(f"only {cfg['max_scans']} of {len(recent)} latest-version dependencies checked")
            recent = recent[:cfg["max_scans"]]
        todo += recent
        budget = max(5.0, deadline - _t.monotonic())
        scanned = scan_engine.scan_packages([(r["name"], r["version"]) for r in todo], budget=budget) if todo else []
        from post_rules import apply as post_apply
        for r, result in zip(todo, scanned):
            rec = package_record(r["name"], r["version"], result)
            rec["via"] = clean(" → ".join(r["via"] + [r["name"]]), 160)
            try:
                new_verdict, fired = post_apply(result, r["version"], osv_ok, None, None)
            except Exception:
                new_verdict, fired = result.verdict, None
            if fired:
                rec["verdict"] = new_verdict
                label = "known malicious version" if fired["rule"] == "known_malicious" else POST_LABELS.get(fired["rule"], fired["rule"])
                rec["evidence"] = [{"rule": fired["rule"], "label": label,
                                    "location": ", ".join(fired.get("ids", [])) or "dependency", "snippet": "", "count": 1}] + \
                                  [e for e in rec["evidence"] if e.get("rule") != "score"]
                rec["headline"] = label
                if fired["rule"] == "known_malicious":
                    rec["malicious_ids"] = fired["ids"]
            out.add(rec, rec["verdict"], dependency=True)
        return {"found": len(found), "osv_checked": bool(osv_ok and found), "scanned": len(todo),
                "malicious": len(malicious), "notes": [clean(n, 160) for n in notes]}
    except Exception as e:
        return {"error": clean(f"{type(e).__name__}: {e}", 160)}


CHECK = Check("pypi", lambda p: bool(p.packages), run, on_timeout)
