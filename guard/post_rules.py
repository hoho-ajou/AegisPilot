"""
AegisPilot - rules applied after the scan, before the policy stage.

Which rules run, in what order, on which scan verdicts and with what result - and every number and pattern they use -
are in guard/rules/post.json. This module only knows how to check each one. A rule never lowers a verdict.

  known_malicious  OSV lists this exact release as malicious (MAL-... or an advisory about a takeover / injected code).
                Always BLOCK. Checked even when the release can no longer be downloaded: compromised releases are usually
                deleted from PyPI, and the scan then only said "version does not exist" (measured 2026-10-15 on
                num2words 0.5.15 and ultralytics 8.3.41), losing the fact that it was malware.
  typosquat     the name is 1-2 edits from a popular package (scan_engine.typosquat_check) and nothing else fired: used to
                ALLOW (weight 0.15 < threshold 0.25), so `requets` with clean code passed. Now REVIEW unless the project is
                older than TYPOSQUAT_ESTABLISHED_DAYS (cattrs, cchardet, grequests: 8-14 years old, the only hits among
                ~1,650 ordinary names) or the names differ only in separators/case (typing_extensions).
  osv_unavailable  OSV (known vulnerabilities and malicious releases) could not be reached while the scan ran.
                scan_engine.query_osv returns [] on any error, so an outage read as "no known vulnerability" and a known
                malicious or CRITICAL release could pass silently. One probe per install command,
                run beside the scan: a query that must return records (OSV_PROBE has known advisories). If it fails, an
                ALLOW becomes REVIEW.
  new_risky_code  code added in THIS release that ordinary releases almost never add (import-time command/network
                call, a binary named .py, a new .pth, an encoded payload), compared with the release before it; when the
                previous release already had it, a binary search finds when it first appeared (version_diff.py).
  late_file     the file pip installs was added to this (old) release recently, long after the release came out:
                a stolen token can add a wheel to an existing version even though it cannot replace one.
  new_package   the project was first published less than NEW_PACKAGE_DAYS ago. Slopsquatting (an attacker registers
                a name AI models invent) and most freshly made malicious packages look exactly like this, while the code
                can look clean. Measured 2026-10-15: projects younger than 30 days
                among popular 63 / top-1000 / random 450 of the top 8000 / long-tail 100: 0% / 0% / 0% / 0%. The same
                signal used to add only 0.05 to the score (reputation weight), so a new package always passed.
"""
from __future__ import annotations

import re

import rule_engine

RULES = rule_engine.current()
NEW_PACKAGE_DAYS = RULES.new_package_days
TYPOSQUAT_ESTABLISHED_DAYS = RULES.typosquat_established_days   # a project older than this is not a squat by name alone
_MALICIOUS = RULES.malicious_text
OSV_PROBE = RULES.osv_probe              # a release with several fixed advisories: a working OSV always returns some
OSV_PROBE_TIMEOUT = RULES.osv_probe_timeout


def osv_reachable(timeout: float = OSV_PROBE_TIMEOUT) -> bool:
    """True when OSV answered with real records. An error, a timeout or an empty/odd answer (a proxy, a captive portal)
    is False: the scan's own empty OSV results cannot then be trusted."""
    import json
    import urllib.request
    try:
        from scan_engine import OSV_QUERY_URL
    except Exception:
        OSV_QUERY_URL = "https://api.osv.dev/v1/query"
    name, version = OSV_PROBE
    req = urllib.request.Request(OSV_QUERY_URL, data=json.dumps({"package": {"name": name, "ecosystem": "PyPI"},
                                                                   "version": version}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(2 * 1024 * 1024))
        return bool(isinstance(data, dict) and data.get("vulns"))
    except Exception:
        return False


def new_package_days(result) -> int | None:
    age = getattr(getattr(result, "features", None), "package_age_days", None)
    if age is None or age >= NEW_PACKAGE_DAYS or not getattr(result.features, "fetch_ok", False):
        return None
    return max(0, int(age))


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def typosquat_of(result) -> str | None:
    """The popular name this one imitates, when that should be asked about."""
    f = getattr(result, "features", None)
    if f is None or not getattr(f, "fetch_ok", False):
        return None
    d, pop = getattr(f, "min_edit_distance", None), getattr(f, "closest_popular_name", None)
    if d is None or not pop:
        return None
    t = RULES.sub["typosquat"]
    max_d = int(t["max_distance_short"]) if len(f.name) <= int(t["short_name_len"]) else int(t["max_distance"])
    if not (0 < d <= max_d) or _norm(f.name) == _norm(pop):
        return None
    age = getattr(f, "package_age_days", None)
    if age is not None and age >= TYPOSQUAT_ESTABLISHED_DAYS:
        return None
    return pop


def known_malicious(result, version: str | None = None) -> list[str]:
    """Ids of OSV records that call this exact release malicious ([] when none or unknown)."""
    f = getattr(result, "features", None)
    if f is None:
        return []
    vulns = getattr(f, "osv_vulns", None) or []
    ver = version or getattr(f, "resolved_version", None) or getattr(f, "version", None)
    if not vulns and getattr(f, "fetch_error", None) and ver:
        try:
            from scan_engine import query_osv
            eco = getattr(f, "ecosystem", "pypi")
            vulns = query_osv(f.name, ver) if eco == "pypi" else query_osv(f.name, ver, eco)
        except Exception:
            vulns = []
    ids = []
    for v in vulns or []:
        vid = str(v.get("id", ""))
        text = f"{v.get('summary') or ''} {(v.get('details') or '')[:RULES.malicious_details_chars]}"
        if vid.startswith(RULES.malicious_id_prefixes) or _MALICIOUS.search(text):
            ids.append(vid)
    return ids


def _fires(rule_id: str, result, version, osv_ok: bool, vdiff, late) -> dict | None:
    """What a rule found (the record kept in the decision), or None."""
    if rule_id == "known_malicious":
        mal = known_malicious(result, version) if osv_ok else []
        return {"ids": mal[:RULES.malicious_max_ids]} if mal else None
    if rule_id == "new_risky_code":
        return dict(vdiff) if vdiff and vdiff.get("signals") else None
    if rule_id == "late_file":
        return dict(late) if late else None
    if rule_id == "osv_unavailable":
        return {} if not osv_ok and not getattr(getattr(result, "features", None), "osv_vulns", None) else None
    if rule_id == "typosquat":
        squat = typosquat_of(result)
        return {"of": squat} if squat else None
    if rule_id == "new_package":
        days = new_package_days(result)
        return {"days": days} if days is not None else None
    raise ValueError(rule_id)


def apply(result, version: str | None = None, osv_ok: bool = True, vdiff: dict | None = None,
          late: dict | None = None) -> tuple[str, dict | None]:
    """(verdict after the rules, the rule that fired or None). osv_ok=False: OSV could not be reached during this scan.
    vdiff: version_diff.check() for this package (risky code new in this release), None when nothing was found.
    The rules of post.json are tried in order; the first that applies to the scan verdict and fires decides."""
    for rule in RULES.post_rules:
        if rule["applies_to"] != "any" and result.verdict not in rule["applies_to"]:
            continue
        found = _fires(rule["id"], result, version, osv_ok, vdiff, late)
        if found is not None:
            return rule["verdict"], {"rule": rule["id"], **found}
    return result.verdict, None
