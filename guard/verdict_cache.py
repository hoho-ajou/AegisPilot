"""
AegisPilot - cache of scan verdicts for the exact file an install would get (on by default; AEGIS_CACHE=0 turns it off).

Why: a command is one decision. When one package of `pip install -r requirements.txt` is held, the agent changes that
line and runs the install again - and every package was scanned again (20 packages: about 20 s, twice that with ML).

What is reused, and only inside one command's decision (guard_core.check_parsed opens the scope; a lone scan such as
guard_cli scan or the benchmark never reads or writes it):
  - a scan verdict of ALLOW, for 6 hours;
  - keyed by the file the installer would get: PyPI name, version, file name and its SHA-256 (a wheel and an sdist are
    separate entries, so a file added to an old release later - pyyaml 6.0.1 got musllinux wheels 184 days on - is a
    new entry), npm name, version and the registry's integrity hash;
  - never for a release under a day old (its rules depend on the hour) or a scan that did not finish.
On every reuse OSV is asked again: a cached version with any OSV record now is scanned again (a release reported as
malicious after the scan is the usual case, not a changed file). A new guard version, new rules or ML models, or
ML switched on or off empties the cache.

The cache lives in <project>/.aegis/cache/ (a protected path: writing it through the agent's tools asks the person).
An agent able to plant an entry by other means can already run code that installs around the guard; the entries are
plain JSON (never pickle), and the OSV check still runs on a planted one.
"""
from __future__ import annotations

import dataclasses
import json
import re
import threading
import time
from pathlib import Path

TTL_SECONDS = 6 * 3600
MAX_ENTRIES = 4000

_lock = threading.Lock()
_state: dict = {"dir": None, "doc": None, "dirty": False}


def enabled() -> bool:
    import switches
    return switches.get("AEGIS_CACHE", "1") != "0"           # built guard: system config only


def fingerprint() -> str:
    """What a reused verdict depends on besides the file: the guard's code version, its rules, the ML models and
    whether ML runs. Any change empties the cache."""
    import hashlib
    parts = []
    try:
        import rule_engine
        parts.append(rule_engine.current().fingerprint)
    except Exception:
        parts.append("rules?")
    guard = Path(__file__).resolve().parent
    for rel in ("ml/models.json", "scan_engine.py", "behavior/__init__.py"):
        try:
            parts.append(hashlib.sha256((guard / rel).read_bytes()).hexdigest()[:16])
        except OSError:
            parts.append(rel + "?")
    try:
        import ml_bridge
        parts.append("ml-on" if ml_bridge.ml_enabled() else "ml-off")
    except Exception:
        parts.append("ml?")
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]


def _path(project_dir) -> Path:
    return Path(project_dir) / ".aegis" / "cache" / "verdicts.json"


def begin(project_dir) -> None:
    """Open the cache of one command's decision (guard_core.check_parsed)."""
    with _lock:
        _state.update(dir=None, doc=None, dirty=False)
        if not project_dir or not enabled():
            return
        try:
            doc = json.loads(_path(project_dir).read_text())
            if not isinstance(doc, dict) or doc.get("fp") != fingerprint() or not isinstance(doc.get("entries"), dict):
                doc = {"fp": fingerprint(), "entries": {}}         # another guard, rules or models: start empty
                _state["dirty"] = True
        except (OSError, ValueError):
            doc = {"fp": fingerprint(), "entries": {}}
        _state.update(dir=str(project_dir), doc=doc)


def end() -> None:
    """Write what this command added and close."""
    with _lock:
        d, doc, dirty = _state["dir"], _state["doc"], _state["dirty"]
        _state.update(dir=None, doc=None, dirty=False)
    if not (d and doc and dirty):
        return
    try:
        now = time.time()
        entries = {k: e for k, e in doc["entries"].items() if now - float(e.get("t", 0)) < TTL_SECONDS}
        doc["entries"] = dict(sorted(entries.items(), key=lambda kv: -kv[1].get("t", 0))[:MAX_ENTRIES])
        import safe_write                               # .aegis is agent-writable: never follow a planted link
        safe_write.write_text(Path(d) / ".aegis", "cache/verdicts.json", json.dumps(doc, ensure_ascii=False))
    except Exception:
        pass


def key(ecosystem: str, name: str, version: str | None, file_id: str | None) -> str | None:
    """The cache key of the exact file an install gets, None when it is not known exactly."""
    if not version or not file_id or not re.fullmatch(r"[0-9A-Za-z.+!_-]{1,64}", str(version)):
        return None
    return f"{ecosystem}:{re.sub(r'[-_.]+', '-', name).lower()}=={version}#{file_id}"


def get(k: str | None):
    """The cached ALLOW verdict for this key (a Verdict), or None."""
    if not k:
        return None
    with _lock:
        doc = _state["doc"]
        e = (doc or {}).get("entries", {}).get(k)
    if not e:
        return None
    try:
        if time.time() - float(e["t"]) >= TTL_SECONDS:
            return None
        import scan_engine
        d = e["v"]
        if d.get("verdict") != "ALLOW":
            return None
        return scan_engine.Verdict(d["verdict"], d["score"], d["reasons"], scan_engine.ScanFeatures(**d["features"]))
    except Exception:
        return None                                    # a damaged entry is just a miss


def put(k: str | None, verdict) -> None:
    """Remember a finished ALLOW scan (anything else is scanned again next time)."""
    if not k or getattr(verdict, "verdict", None) != "ALLOW":
        return
    f = getattr(verdict, "features", None)
    if f is None or getattr(f, "fetch_error", None) or getattr(f, "command_stopped", False):
        return
    try:
        v = dataclasses.asdict(verdict)
        json.dumps(v)                                  # only what JSON can hold
    except Exception:
        return
    with _lock:
        if _state["doc"] is None:
            return
        _state["doc"]["entries"][k] = {"t": time.time(), "v": v}
        _state["dirty"] = True
