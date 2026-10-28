"""
AegisPilot - opt-in cache of scan verdicts for exact package versions (AEGIS_CACHE=1; off by default).

Re-running an install (e.g. after an agent fixed one line) rescans every package. With the cache on, a (name, exact version)
scanned in the last TTL_SECONDS is reused.

Why it is off by default: the cache lives in a folder the agent can write (<project>/.aegis/cache/), so a forged "ALLOW"
entry would skip the scan. The folder is a protected path (writing it through the agent's tools asks the person first),
entries are plain JSON (never pickle: unpickling a writable file is code execution), only exact versions are cached
("latest" moves), entries expire, and an entry made under other rules (a guard update, a rule module) is not
reused. That narrows the risk; it does not remove it. Turn it on where speed matters more.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import tempfile
import time
from pathlib import Path

TTL_SECONDS = 6 * 3600
MAX_ENTRIES = 2000


def enabled() -> bool:
    import switches
    return switches.get("AEGIS_CACHE", "0") == "1"           # built guard: system config only


def _key(name: str, version: str | None) -> str | None:
    if not version or not re.fullmatch(r"[0-9A-Za-z.+!_-]{1,40}", version):
        return None
    return re.sub(r"[-_.]+", "-", name).lower() + "==" + version


def _rules() -> str:
    """The fingerprint of the rules in use (base files + rule modules): a verdict made under other rules is not reused."""
    import rule_engine
    return rule_engine.current().fingerprint


def _path(project_dir) -> Path:
    return Path(project_dir) / ".aegis" / "cache" / "verdicts.json"


def _load(project_dir) -> dict:
    try:
        doc = json.loads(_path(project_dir).read_text())
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def lookup(project_dir, items):
    """(cached verdicts by index, items still to scan with their indices)."""
    import scan_engine
    doc, now = _load(project_dir), time.time()
    hits, todo = {}, []
    for i, (name, version) in enumerate(items):
        e = doc.get(_key(name, version) or "")
        try:
            if e and now - float(e["t"]) < TTL_SECONDS and e.get("r") == _rules():
                d = e["v"]
                hits[i] = scan_engine.Verdict(d["verdict"], d["score"], d["reasons"], scan_engine.ScanFeatures(**d["features"]))
                continue
        except Exception:
            pass                                   # a damaged entry is just a miss
        todo.append((i, (name, version)))
    return hits, todo


def store(project_dir, items, verdicts) -> None:
    try:
        doc, now = _load(project_dir), time.time()
        for (name, version), v in zip(items, verdicts):
            k = _key(name, version)
            fetch_error = getattr(getattr(v, "features", None), "fetch_error", None)
            if k and not fetch_error:              # failures (network, timeout) are never cached
                doc[k] = {"t": now, "r": _rules(), "v": dataclasses.asdict(v)}
        doc = dict(sorted(doc.items(), key=lambda kv: -kv[1].get("t", 0))[:MAX_ENTRIES])
        p = _path(project_dir)
        p.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".verdicts.", suffix=".tmp")
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, ensure_ascii=False)
        os.replace(tmp, p)
    except Exception:
        pass


def forget(project_dir, items) -> None:
    """Drop these packages' entries (used when OSV was unreachable: a verdict made without it must not be reused)."""
    try:
        doc = _load(project_dir)
        keys = {_key(n, v) for n, v in items} - {None}
        if not keys & doc.keys():
            return
        for k in keys:
            doc.pop(k, None)
        p = _path(project_dir)
        fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".verdicts.", suffix=".tmp")
        with os.fdopen(fd, "w") as fh:
            json.dump(doc, fh, ensure_ascii=False)
        os.replace(tmp, p)
    except Exception:
        pass


def scan_with_cache(project_dir, items, scan):
    hits, todo = lookup(project_dir, items)
    fresh = scan([it for _, it in todo]) if todo else []
    store(project_dir, [it for _, it in todo], fresh)
    out = [None] * len(items)
    for i, v in hits.items():
        out[i] = v
    for (i, _it), v in zip(todo, fresh):
        out[i] = v
    return out
