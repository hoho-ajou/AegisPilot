"""
AegisPilot - transitive dependencies.

`pip install fastapi` also installs starlette, pydantic, anyio, ... and until now only fastapi was scanned. A
compromised release of one of those would pass. Scanning every dependency of every install would be slow, so:

  1. The tree is walked from PyPI metadata alone (nothing is installed or built): each dependency gets the version pip
     would pick - the newest final release that satisfies the declared range - or, for a lock-file install, the
     version the lock pins.
  2. Every (name, version) found goes to OSV in ONE batch request: a release OSV lists as malicious (MAL-...) is
     reported however old it is.
  3. Releases uploaded within `recent_days` are fully scanned like a direct package. A hijacked release is almost
     always a fresh one (DataDog compromised set: all 29 within days of the attack), while the rest of a dependency
     tree is usually months or years old - so this covers the likely case for a few extra scans.

Limits (depth, number of packages, number of full scans, time) are in guard/rules/post.json "transitive". Hitting a
limit is recorded in the decision, never a silent pass of what was not looked at.
"""
from __future__ import annotations

import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import collect
import rule_engine

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def settings() -> dict:
    return rule_engine.current().transitive


def _uploaded(meta: dict, version: str) -> datetime | None:
    files = [f for f in (meta.get("releases") or {}).get(version) or [] if not f.get("yanked")]
    try:
        return min(datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files)
    except (ValueError, KeyError):
        return None


def pick_version(meta: dict, spec: str) -> str | None:
    """The version pip would install for `spec`: the newest non-yanked final release in range (pre-releases only when
    the range itself names one)."""
    try:
        from _vendor.packaging.specifiers import SpecifierSet
        from _vendor.packaging.version import InvalidVersion, Version
    except Exception:
        return (meta.get("info") or {}).get("version")
    try:
        ss = SpecifierSet(spec or "")
    except Exception:
        ss = SpecifierSet("")
    best = None
    for v, files in (meta.get("releases") or {}).items():
        if not files or all(f.get("yanked") for f in files):
            continue
        try:
            ver = Version(v)
        except InvalidVersion:
            continue
        if ver.is_prerelease and not ss.prereleases:
            continue
        if ss.contains(ver, prereleases=True) and (best is None or ver > best[0]):
            best = (ver, v)
    return best[1] if best else None


def walk(direct: list[dict], fetch_meta, lock_pins: dict | None = None, now: datetime | None = None,
         deadline: float | None = None) -> tuple[list[dict], list[str]]:
    """direct: [{"name", "version", "dependencies": [{"name", "spec"}]}] for the packages the command names.
    Returns (dependencies found: [{"name", "version", "via": [names], "uploaded", "recent"}], notes on limits hit)."""
    cfg = settings()
    now = now or datetime.now(timezone.utc)
    recent_cut = now - timedelta(days=int(cfg["recent_days"]))
    lock_pins = lock_pins or {}
    seen = {collect.normalize_name(d["name"]) for d in direct}
    level = [(dep["name"], dep.get("spec", ""), [d["name"]]) for d in direct for dep in d.get("dependencies") or []]
    found: list[dict] = []
    notes: list[str] = []
    meta_cache: dict = {}

    def one(item):
        name, spec, via = item
        try:
            meta = meta_cache.get(name) or fetch_meta(name)
            meta_cache[name] = meta
        except Exception as e:
            return {"name": name, "version": None, "via": via, "error": type(e).__name__}
        version = lock_pins.get(collect.normalize_name(name)) or pick_version(meta, spec)
        if not version:
            return {"name": name, "version": None, "via": via, "error": "no matching version"}
        up = _uploaded(meta, version)
        try:
            deps = collect.fetch_requires(name, version, meta)
        except Exception:
            deps = []
        return {"name": collect.normalize_name(name), "version": version, "via": via,
                "uploaded": up.date().isoformat() if up else None, "recent": bool(up and up >= recent_cut),
                "dependencies": deps}

    with ThreadPoolExecutor(int(cfg["workers"])) as pool:
        for depth in range(1, int(cfg["max_depth"]) + 1):
            todo = []
            for name, spec, via in level:
                key = collect.normalize_name(name)
                if key in seen:
                    continue
                seen.add(key)
                todo.append((name, spec, via))
            if not todo:
                break
            room = int(cfg["max_packages"]) - len(found)
            if room <= 0:
                notes.append(f"more than {cfg['max_packages']} transitive dependencies: the rest were not checked")
                break
            if len(todo) > room:
                notes.append(f"more than {cfg['max_packages']} transitive dependencies: {len(todo) - room} were not checked")
                todo = todo[:room]
            if deadline is not None and time.monotonic() > deadline:
                notes.append("transitive dependencies not fully checked within the time limit")
                break
            results = list(pool.map(one, todo))
            found += results
            level = [(dep["name"], dep.get("spec", ""), r["via"] + [r["name"]])
                     for r in results if r.get("version") for dep in r.get("dependencies") or []]
        else:
            if level:
                notes.append(f"dependencies deeper than {cfg['max_depth']} levels were not checked")
    for r in found:
        r.pop("dependencies", None)
    return found, notes


def osv_malicious(found: list[dict], timeout: float = 15) -> dict[tuple[str, str], list[str]]:
    """{(name, version): [MAL-... ids]} for every found release OSV lists as malicious, in one batch request."""
    items = [r for r in found if r.get("version")]
    if not items:
        return {}
    payload = {"queries": [{"package": {"name": r["name"], "ecosystem": "PyPI"}, "version": r["version"]} for r in items]}
    req = urllib.request.Request(OSV_BATCH_URL, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read(8 * 1024 * 1024))
    out = {}
    for r, res in zip(items, data.get("results") or []):
        ids = [v.get("id", "") for v in (res or {}).get("vulns") or [] if str(v.get("id", "")).startswith(
            rule_engine.current().malicious_id_prefixes)]
        if ids:
            out[(r["name"], r["version"])] = ids
    return out
