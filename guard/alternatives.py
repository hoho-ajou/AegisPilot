"""
AegisPilot - one exact version to install instead of a held one, picked from the registry's own records.

The fix the guard names is a single version, never a range: `requests>=2.33.0` would install whatever is newest when the
agent runs it (maybe a release from the last hour, maybe a hijacked one), which is not what was looked at. A candidate
must be:

  - a real release with files that are not yanked (PyPI) / a published version (npm), not a pre-release unless the held
    version is one;
  - older than the fresh-release limit (24 hours by default);
  - free of any OSV record, vulnerabilities and malicious-package records alike (one batch request for all candidates).

Which candidates come first:
  - a known vulnerability with a fixed version: the newest version from that fixed version up. Not the lowest: an old
    fixed version often has no wheel for today's Python and fails to build (pyyaml 5.4 on Python 3.12, measured);
  - anything else (a release under a day old, late files, new risky code, a malicious release): the newest version
    below the held one.

Only the records are read here; the code of the picked version is not. It is checked like any install when the agent
runs it (the hook sees the new command). None when nothing qualifies or OSV cannot be reached.
"""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timezone

import net

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_CANDIDATES = 8
TIMEOUT = 10


def _osv_clean(ecosystem: str, name: str, versions: list[str]) -> list[str]:
    """The versions OSV has no record for (any id), in the order given. Raises when OSV cannot be read."""
    if not versions:
        return []
    payload = {"queries": [{"package": {"name": name, "ecosystem": ecosystem}, "version": v} for v in versions]}
    req = urllib.request.Request(OSV_BATCH_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with net.urlopen(req, timeout=TIMEOUT) as resp:
        data = json.loads(resp.read(8 * 1024 * 1024))
    results = data.get("results") or []
    if len(results) != len(versions):
        raise ValueError("OSV batch answer does not match the query")
    return [v for v, res in zip(versions, results) if not (res or {}).get("vulns")]


def _order(cands: list, cur, fix) -> list[str]:
    """cands = [(parsed, text)]; the order to try them in (see the module text)."""
    if fix is not None:
        up = sorted((c for c in cands if c[0] >= fix), key=lambda c: c[0], reverse=True)
        return [t for _p, t in up]
    down = sorted((c for c in cands if cur is None or c[0] < cur), key=lambda c: c[0], reverse=True)
    return [t for _p, t in down]


def pypi(name: str, meta: dict, current: str | None, fix_version: str | None, hours: float,
         now: datetime | None = None) -> str | None:
    try:
        from _vendor.packaging.version import InvalidVersion, Version
    except Exception:
        return None
    now = now or datetime.now(timezone.utc)

    def ver(s):
        try:
            return Version(str(s))
        except (InvalidVersion, TypeError):
            return None
    cur, fix = ver(current), (ver(fix_version) if fix_version else None)
    cands = []
    for v, files in (meta.get("releases") or {}).items():
        pv = ver(v)
        live = [f for f in files or [] if not f.get("yanked")]
        if pv is None or not live or v == current or (pv.is_prerelease and not (cur is not None and cur.is_prerelease)):
            continue
        times = [f.get("upload_time_iso_8601") for f in live if f.get("upload_time_iso_8601")]
        try:
            first = min(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times)
        except ValueError:
            continue
        if (now - first).total_seconds() < hours * 3600:
            continue
        cands.append((pv, v))
    order = _order(cands, cur, fix)[:MAX_CANDIDATES]
    try:
        clean = _osv_clean("PyPI", name, order)
    except Exception:
        return None
    return clean[0] if clean else None


def npm(name: str, meta: dict, times: dict | None, current: str | None, fix_version: str | None, hours: float,
        now: datetime | None = None) -> str | None:
    from sources import npm as src
    now = now or datetime.now(timezone.utc)
    if not times:
        return None
    cur = src.parse(current or "")
    fix = src.parse(fix_version) if fix_version else None
    cands = []
    for v, doc in (meta.get("versions") or {}).items():
        p = src.parse(v)
        if p is None or v == current or (isinstance(doc, dict) and doc.get("deprecated")):
            continue
        if p[3] is not None and not (cur is not None and cur[3] is not None):
            continue
        try:
            when = datetime.fromisoformat(str(times.get(v)).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if (now - when).total_seconds() < hours * 3600:
            continue
        cands.append((src._key(p), v))
    order = _order(cands, src._key(cur) if cur else None, src._key(fix) if fix else None)[:MAX_CANDIDATES]
    try:
        clean = _osv_clean("npm", name, order)
    except Exception:
        return None
    return clean[0] if clean else None


def fix_version_of(vulns: list, current: str | None) -> str | None:
    """The version that fixes every listed vulnerability (review_report's rule), None when one has no fixed version."""
    try:
        from review_report import _advice_fields

        class _F:
            pass
        f = _F()
        f.osv_vulns, f.resolved_version, f.osv_max_severity = vulns, current, None
        f.min_edit_distance, f.closest_popular_name, f.fetch_error = None, None, None
        adv = _advice_fields(f)
    except Exception:
        return None
    if adv.get("fix_missing"):
        return None
    return adv.get("fix_version")
