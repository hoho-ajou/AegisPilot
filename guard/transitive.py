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

import net
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
    """direct: [{"name", "version", "extras", "dependencies": [{"name", "spec", "extras"}]}] for the packages the command
    names. Returns (dependencies found: [{"name", "version", "via": [names], "uploaded", "recent"}], notes on limits hit).

    A dependency asked for with extras (`uvicorn[standard]`) brings their dependencies too. A package met again with
    extras not followed yet (a plain `uvicorn` first, `uvicorn[standard]` later) is opened again for those extras only:
    it is listed once, its added dependencies are walked like any other."""
    cfg = settings()
    now = now or datetime.now(timezone.utc)
    recent_cut = now - timedelta(days=int(cfg["recent_days"]))
    lock_pins = lock_pins or {}
    # normalized name -> (version, extras followed so far); the direct packages are already open
    opened: dict[str, tuple[str | None, set]] = {
        collect.normalize_name(d["name"]): (d.get("version"), {collect.normalize_extra(e) for e in d.get("extras") or ()})
        for d in direct}
    level = [(dep["name"], dep.get("spec", ""), set(dep.get("extras") or ()), [d["name"]])
             for d in direct for dep in d.get("dependencies") or []]
    found: list[dict] = []
    notes: list[str] = []
    meta_cache: dict = {}

    def meta_of(name):
        meta = meta_cache.get(name) or fetch_meta(name)
        meta_cache[name] = meta
        return meta

    def one(item):
        name, spec, extras, via = item
        try:
            meta = meta_of(name)
        except Exception as e:
            return {"name": name, "version": None, "via": via, "error": type(e).__name__}
        version = lock_pins.get(collect.normalize_name(name)) or pick_version(meta, spec)
        if not version:
            return {"name": name, "version": None, "via": via, "error": "no matching version"}
        up = _uploaded(meta, version)
        try:
            deps = collect.fetch_requires(name, version, meta, extras=extras)
        except Exception:
            deps = []
        return {"name": collect.normalize_name(name), "version": version, "via": via,
                "uploaded": up.date().isoformat() if up else None, "uploaded_at": up.isoformat() if up else None, "recent": bool(up and up >= recent_cut),
                "dependencies": deps}

    def more(item):
        """A package already open, met with more extras: only the dependencies those extras add."""
        name, version, extras, via = item
        try:
            deps = collect.fetch_requires(name, version, meta_of(name), extras=extras)
        except Exception:
            deps = []
        return {"name": collect.normalize_name(name), "via": via, "dependencies": deps}

    with ThreadPoolExecutor(int(cfg["workers"])) as pool:
        for depth in range(1, int(cfg["max_depth"]) + 1):
            todo, again, pending = [], [], {}
            for name, spec, extras, via in level:
                key = collect.normalize_name(name)
                extras = {collect.normalize_extra(e) for e in extras}
                if key in pending:                       # asked for twice on this level: one lookup with all the extras
                    todo[pending[key]][2].update(extras)
                    continue
                if key in opened:
                    version, done = opened[key]
                    if version and not extras <= done:
                        opened[key] = (version, done | extras)
                        again.append((name, version, done | extras, via))
                    continue
                pending[key] = len(todo)
                todo.append((name, spec, set(extras), via))
            if not todo and not again:
                break
            room = int(cfg["max_packages"]) - len(found)
            if todo and room <= 0:
                notes.append(f"more than {cfg['max_packages']} transitive dependencies: the rest were not checked")
                break
            if len(todo) > room:
                notes.append(f"more than {cfg['max_packages']} transitive dependencies: {len(todo) - room} were not checked")
                todo = todo[:room]
            if deadline is not None and time.monotonic() > deadline:
                notes.append("transitive dependencies not fully checked within the time limit")
                break
            results = list(pool.map(one, todo))
            for r, (name, _spec, extras, _via) in zip(results, todo):
                opened[collect.normalize_name(name)] = (r.get("version"), extras)
            found += results
            results += list(pool.map(more, again))
            level = [(dep["name"], dep.get("spec", ""), set(dep.get("extras") or ()), r["via"] + [r["name"]])
                     for r in results if r.get("dependencies") for dep in r["dependencies"]]
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
    with net.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read(8 * 1024 * 1024))
    out = {}
    for r, res in zip(items, data.get("results") or []):
        ids = [v.get("id", "") for v in (res or {}).get("vulns") or [] if str(v.get("id", "")).startswith(
            rule_engine.current().malicious_id_prefixes)]
        if ids:
            out[(r["name"], r["version"])] = ids
    return out
