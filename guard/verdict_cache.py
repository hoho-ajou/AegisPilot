"""
AegisPilot - cache of scan verdicts for the exact file an install would get (on by default; AEGIS_CACHE=0 turns it off).

Why: a command is one decision. When one package of `pip install -r requirements.txt` is held, the agent changes that
line and runs the install again - and every package was scanned again (20 packages: about 20 s, twice that with ML).

What is reused, and only inside one command's decision (guard_core.check_parsed opens the scope; a lone scan such as
guard_cli scan or the benchmark never reads or writes it):
  - a finished scan verdict, for 6 hours: an ALLOW is not scanned again, a held package (REVIEW, BLOCK) that comes back
    is held again at once - the same verdict a scan of the same file would give;
  - keyed by the file the installer would get: PyPI name, version, file name and its SHA-256 (a wheel and an sdist are
    separate entries, so a file added to an old release later - pyyaml 6.0.1 got musllinux wheels 184 days on - is a
    new entry), npm name, version and the registry's integrity hash;
  - never for a release under a day old (its rules depend on the hour) or a scan that did not finish.
On every reuse OSV is asked again: when its records of the version differ from those at the scan, the version is
scanned again (a release reported as malicious after the scan is the usual case, not a changed file). The rules that
run after the scan (vulnerabilities, a fresh release, the allow / deny lists) run again on every reuse. A new guard version, new rules or ML models, or
ML switched on or off empties the cache.

The cache lives in <project>/.aegis/cache/ (a protected path: writing it through the agent's tools asks the person).
An agent able to plant an entry by other means can already run code that installs around the guard; the entries are
plain JSON (never pickle), and the OSV check still runs on a planted one.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import threading
import time
from pathlib import Path

TTL_SECONDS = 6 * 3600
MAX_ENTRIES = 4000

_lock = threading.Lock()
_state: dict = {"dir": None, "doc": None, "dirty": False, "fp": None}


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


def _read(project_dir) -> dict | None:
    try:
        doc = json.loads(_path(project_dir).read_text())
        return doc if isinstance(doc, dict) and isinstance(doc.get("entries"), dict) else None
    except (OSError, ValueError):
        return None


def begin(project_dir) -> None:
    """Open the cache of one command's decision (guard_core.check_parsed)."""
    with _lock:
        _state.update(dir=None, doc=None, dirty=False, fp=None)
        if not project_dir or not enabled():
            return
        fp = fingerprint()                              # once per command
        doc = _read(project_dir)
        if doc is None or doc.get("fp") != fp:
            doc = {"fp": fp, "entries": {}, "held": {}}  # another guard, rules or models: start empty
        _state.update(dir=str(project_dir), doc=doc, fp=fp)


def _merge(mine: dict, theirs: dict | None, now: float) -> dict:
    """The file as it is now (other hooks may have written it since this one read it) and this command's view, merged:
    every entry keeps its own time and expires on its own; the newer of two wins."""
    if not theirs or theirs.get("fp") != mine.get("fp"):
        theirs = {"entries": {}, "held": {}}
    entries = dict(theirs.get("entries") or {})
    for k, e in (mine.get("entries") or {}).items():
        if k not in entries or float(e.get("t", 0)) >= float(entries[k].get("t", 0)):
            entries[k] = e
    held = dict(theirs.get("held") or {})          # time noted; -time = used up then (the newer one wins)
    for k, t in (mine.get("held") or {}).items():
        if abs(float(t)) >= abs(float(held.get(k, 0))):
            held[k] = t
    times = dict(theirs.get("times") or {})
    for k, e in (mine.get("times") or {}).items():
        if k not in times or float(e.get("t", 0)) >= float(times[k].get("t", 0)):
            times[k] = e
    entries = {k: e for k, e in entries.items() if now - float(e.get("t", 0)) < TTL_SECONDS}
    held = {k: t for k, t in held.items() if now - abs(float(t)) < AS_IS_SECONDS}
    times = {k: e for k, e in times.items() if now - float(e.get("t", 0)) < TTL_SECONDS}
    return {"fp": mine.get("fp"), "entries": dict(sorted(entries.items(), key=lambda kv: -kv[1].get("t", 0))[:MAX_ENTRIES]),
            "held": held, "times": dict(sorted(times.items(), key=lambda kv: -kv[1].get("t", 0))[:MAX_ENTRIES])}


def end() -> None:
    """Merge what this command added into the file (under a lock: hooks of parallel tool calls run at the same time)
    and close."""
    with _lock:
        d, doc, dirty = _state["dir"], _state["doc"], _state["dirty"]
        _state.update(dir=None, doc=None, dirty=False, fp=None)
    if not (d and doc and dirty):
        return
    lock_fd = None
    try:
        import safe_write                               # .aegis is agent-writable: never follow a planted link
        folder = safe_write.real_dir(Path(d) / ".aegis", Path("cache"))
        try:
            import fcntl
            lock_fd = os.open(str(folder / "verdicts.lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except (ImportError, OSError):
            lock_fd = None                              # no lock (Windows): the merge still keeps most of both
        merged = _merge(doc, _read(d), time.time())
        safe_write.write_text(Path(d) / ".aegis", "cache/verdicts.json", json.dumps(merged, ensure_ascii=False))
    except Exception:
        pass
    finally:
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


def key(ecosystem: str, name: str, version: str | None, file_id: str | None) -> str | None:
    """The cache key of the exact file an install gets, None when it is not known exactly."""
    if not version or not file_id or not re.fullmatch(r"[0-9A-Za-z.+!_-]{1,64}", str(version)):
        return None
    return f"{ecosystem}:{re.sub(r'[-_.]+', '-', name).lower()}=={version}#{file_id}"


def get(k: str | None):
    """The cached scan verdict for this key (a Verdict, any verdict), or None. The caller checks OSV again."""
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
        return scan_engine.Verdict(d["verdict"], d["score"], d["reasons"], scan_engine.ScanFeatures(**d["features"]))
    except Exception:
        return None                                    # a damaged entry is just a miss


def put(k: str | None, verdict) -> None:
    """Remember a finished scan, whatever its verdict: an ALLOW is not scanned again, and a held package that comes
    back is held again at once (no scan). Failed or stopped scans are not kept."""
    if not k or getattr(verdict, "verdict", None) not in ("ALLOW", "NEEDS_HUMAN_REVIEW", "BLOCK"):
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


AS_IS_SECONDS = 30 * 60      # auto mode: a held version sent again within this time is the agent going ahead as is


def held_key(rec: dict) -> str | None:
    """A held package of a decision record: ecosystem, name, version (what the agent sends again to go ahead)."""
    name, version = str(rec.get("package") or ""), str(rec.get("version") or "")
    if not name or not version:
        return None
    return f"{rec.get('ecosystem') or 'pypi'}:{re.sub(r'[-_.]+', '-', name).lower()}=={version}"


def held_before(keys: list) -> bool:
    """Every one of these held packages was held (and shown to the agent) by an earlier command within AS_IS_SECONDS."""
    if not keys or None in keys:
        return False
    with _lock:
        held = ((_state["doc"] or {}).get("held") or {})
    now = time.time()
    try:
        return all(k in held and float(held[k]) > 0 and now - float(held[k]) < AS_IS_SECONDS for k in keys)
    except (TypeError, ValueError):
        return False


def note_held(keys: list) -> None:
    """Remember that these packages were held and shown to the agent now (auto mode)."""
    with _lock:
        doc = _state["doc"]
        if doc is None:
            return
        held = doc.setdefault("held", {})
        now = time.time()
        for k in keys:
            if k:
                held[k] = now
        doc["held"] = {k: t for k, t in held.items() if now - abs(float(t)) < AS_IS_SECONDS}
        _state["dirty"] = True


def forget_held(keys: list) -> None:
    """A held package the agent went ahead with: not passed again by the same rule without a new hold."""
    with _lock:
        doc = _state["doc"]
        if doc is None:
            return
        now = time.time()
        for k in keys:
            doc.setdefault("held", {})[k] = -now        # used up now (kept, so an older copy elsewhere cannot revive it)
        _state["dirty"] = True


def active() -> bool:
    with _lock:
        return _state["doc"] is not None


def current_dir() -> str | None:
    """The project folder of the command being decided (for worker processes), None outside one."""
    with _lock:
        return _state["dir"]


def _tkey(name: str, version: str) -> str:
    return f"npm:{name}@{version}"


def published(name: str, version: str) -> str | None:
    """An npm version's publish time read within TTL_SECONDS ("" = known to have none), None when not known."""
    with _lock:
        doc = _state["doc"]
        e = ((doc or {}).get("times") or {}).get(_tkey(name, version))
    try:
        if e and time.time() - float(e["t"]) < TTL_SECONDS:
            return str(e.get("p") or "")
    except (TypeError, ValueError):
        pass
    return None


def note_published(name: str, version: str, when: str) -> None:
    with _lock:
        doc = _state["doc"]
        if doc is None:
            return
        doc.setdefault("times", {})[_tkey(name, version)] = {"t": time.time(), "p": when}
        _state["dirty"] = True

