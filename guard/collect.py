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


def normalize_extra(extra: str) -> str:
    """PEP 685: extra names compare like project names (`Dev`, `dev_tools` -> `dev`, `dev-tools`)."""
    return re.sub(r"[-_.]+", "-", str(extra).strip()).lower()


def parse_extras(text: str | None) -> set[str]:
    """`a, B_c` (the inside of `pkg[...]`) -> {"a", "b-c"}."""
    return {normalize_extra(e) for e in (text or "").split(",") if e.strip()}


def parse_requires(requires_dist: list[str] | None, extras=None, own: str | None = None) -> list[dict]:
    """The dependencies pip installs: [{"name", "spec", "extras"}], one per name, sorted.

    An entry counts when its environment marker is true for THIS interpreter with no extra or with one of the extras
    asked for (`pkg[a,b]`). A package may name itself to pull in more of its own extras (`pkg[all]` -> `pkg[a,b]`):
    those are followed, not listed. Two entries for one name are merged (both ranges apply, the extras add up). Entries
    that cannot be parsed are kept by name (unless they sit behind an extra that was not asked for), never lost."""
    try:
        from _vendor.packaging.requirements import Requirement
    except Exception:                                            # no packaging: fall back to the leading name
        Requirement = None
    own_key = normalize_name(own) if own else None
    wanted = {""} | {normalize_extra(e) for e in (extras or ())}
    parsed = []
    for raw in requires_dist or []:
        try:
            if Requirement is None:
                raise ValueError
            req = Requirement(raw)
            parsed.append((normalize_name(req.name), str(req.specifier), {normalize_extra(e) for e in req.extras}, req.marker, raw))
        except Exception:
            m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", raw)
            if m:
                parsed.append((normalize_name(m.group(1)), "", set(), None, raw))

    def applies(marker, raw) -> bool:
        if marker is None:
            if Requirement is not None or "extra" not in raw.split(";", 1)[-1]:
                return True
            named = set(re.findall(r"extra\s*==\s*['\"]([^'\"]+)['\"]", raw))
            return bool({normalize_extra(x) for x in named} & wanted)
        for extra in wanted:
            try:
                if marker.evaluate({"extra": extra}):
                    return True
            except Exception:
                return True                                      # a marker this cannot evaluate: keep the entry
        return False

    while True:                                                  # own extras can name more own extras
        more = set()
        for name, _spec, req_extras, marker, raw in parsed:
            if own_key and name == own_key and applies(marker, raw):
                more |= req_extras - wanted
        if not more:
            break
        wanted |= more
    out: dict[str, dict] = {}
    for name, spec, req_extras, marker, raw in parsed:
        if (own_key and name == own_key) or not applies(marker, raw):
            continue
        cur = out.setdefault(name, {"name": name, "spec": "", "extras": []})
        if spec and spec not in cur["spec"].split(","):
            cur["spec"] = ",".join(x for x in (cur["spec"], spec) if x)
        cur["extras"] = sorted(set(cur["extras"]) | req_extras)
    return [out[k] for k in sorted(out)]


def requirement_text(dep: dict) -> str:
    """{"name", "spec", "extras"} -> `name[a,b]spec`."""
    extras = dep.get("extras") or []
    return f"{dep['name']}{'[' + ','.join(extras) + ']' if extras else ''}{dep.get('spec') or ''}"


def fetch_release(name: str, resolved: str | None, meta: dict, timeout: int = 15) -> dict:
    """The resolved version's own JSON ({"info", "urls"}). The project JSON's top level describes the LATEST release,
    so a pinned older version needs its own request; the latest one comes from `meta` for free."""
    if resolved and meta.get("info", {}).get("version") != resolved:
        with urllib.request.urlopen(PYPI_VERSION_JSON_URL.format(name=name, version=resolved), timeout=timeout) as r:
            return json.loads(r.read())
    return {"info": meta.get("info", {}), "urls": meta.get("urls", [])}


def fetch_requires(name: str, resolved: str | None, meta: dict, timeout: int = 15, rel: dict | None = None,
                   extras=None) -> list[dict]:
    """The dependencies of the resolved version with these extras (from `rel` when the caller already fetched it)."""
    rel = rel if rel is not None else fetch_release(name, resolved, meta, timeout)
    return parse_requires(rel.get("info", {}).get("requires_dist"), extras, own=name)


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
