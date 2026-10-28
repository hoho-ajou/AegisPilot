"""
AegisPilot - collection helpers: what a package declares and how old/anonymous it is.

Kept apart from scan_engine so the collection stage has one place that turns PyPI metadata into plain data
(dependency list, reputation signals) that the rules, the ML bridge and later the attack-path stage all read.
Pure functions plus one optional network call; nothing downloaded is executed.
"""
from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone

PYPI_VERSION_JSON_URL = "https://pypi.org/pypi/{name}/{version}/json"


def normalize_name(name: str) -> str:
    """PEP 503 name normalization (the form PyPI and pip compare names in)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requires(requires_dist: list[str] | None) -> list[dict]:
    """Direct dependencies that apply to a plain install: [{"name", "spec"}], deduplicated, sorted.
    An entry is dropped when its environment marker is false for THIS interpreter or it only exists behind an
    extra (`extra == "x"`) - pip installs neither by default. Unparsable entries are kept by name, never lost."""
    out: dict[str, dict] = {}
    try:
        from packaging.requirements import Requirement
    except Exception:                                            # no packaging: fall back to the leading name
        Requirement = None
    for raw in requires_dist or []:
        try:
            if Requirement is None:
                raise ValueError
            req = Requirement(raw)
            if req.marker is not None and not req.marker.evaluate({"extra": ""}):
                continue
            name, spec = normalize_name(req.name), str(req.specifier)
        except Exception:
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", raw)
            if not m or "extra ==" in raw:
                continue
            name, spec = normalize_name(m.group(1)), ""
        out.setdefault(name, {"name": name, "spec": spec})
    return [out[k] for k in sorted(out)]


def fetch_release(name: str, resolved: str | None, meta: dict, timeout: int = 15) -> dict:
    """The resolved version's own JSON ({"info", "urls"}). The project JSON's top level describes the LATEST release,
    so a pinned older version needs its own request; the latest one comes from `meta` for free."""
    if resolved and meta.get("info", {}).get("version") != resolved:
        with urllib.request.urlopen(PYPI_VERSION_JSON_URL.format(name=name, version=resolved), timeout=timeout) as r:
            return json.loads(r.read())
    return {"info": meta.get("info", {}), "urls": meta.get("urls", [])}


def fetch_requires(name: str, resolved: str | None, meta: dict, timeout: int = 15, rel: dict | None = None) -> list[dict]:
    """requires_dist of the resolved version (from `rel` when the caller already fetched it)."""
    rel = rel if rel is not None else fetch_release(name, resolved, meta, timeout)
    return parse_requires(rel.get("info", {}).get("requires_dist"))


def reputation_signals(meta: dict, now: datetime | None = None) -> dict:
    """{"maintainer_count": 0|1, "has_description": bool, "age_days": float|None} from the project JSON."""
    info = meta.get("info", {})
    times = [f["upload_time_iso_8601"] for files in meta.get("releases", {}).values() for f in files
             if f.get("upload_time_iso_8601")]
    age = None
    if times:
        earliest = min(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times)
        age = ((now or datetime.now(timezone.utc)) - earliest).total_seconds() / 86400
    return {"maintainer_count": 1 if info.get("maintainer") or info.get("author") else 0,
            "has_description": bool(info.get("description")), "age_days": age}
