"""Facts of one source file, reused by its exact content (AEGIS_FACTS_CACHE=1; off by default).

A large package changes few files per release (next 16.4.2 -> 16.4.3: 73% of the JavaScript bytes are byte-identical),
so what the analysis found in a file is kept under a key of everything the result depends on:

  sha256 of the text, its package-relative name (the code sees it as __filename / __dirname), the phase, the language,
  the rules in use (rule_engine fingerprint: rules/*.json incl. behavior.json and its limits), and the analyzer's own
  source (guard/behavior/*.py). Another guard version, another rule set or another limit is another key.

Only results that depend on nothing but the file are stored ("pure"): the analysis of the file did not ask about
another file (Context.run_file / bundled / nested Python, which can import other modules) and did not ask whether a
path was downloaded while another file had already marked one. A file stopped by a limit (time, steps, size) is not
stored, so the next scan reads it again. Stored: the facts (finding, phase, line, detail), the paths it marked as
downloaded / executable, and the not-analyzed notes; replayed into the Context exactly as the analysis would add them.

Where: ~/.aegis/cache/facts.sqlite (".aegis/" is a protected path: guard_paths.GUARD_FRAGMENTS). A forged entry ("this
content has no facts") would hide that file's code from the guard, so the folder must stay out of the agent's reach; a
process that can write it already runs code as the user (out of scope: threat model). Entries are JSON text in SQLite,
never pickle. AEGIS_FACTS_CACHE_DIR moves it (tests); that is a weakening switch (switches.WEAKENING).
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

MAX_ROWS = 200_000          # ~ 60 next releases' worth of files; the least recently used go first
_conn = None
_code_hash = None


def enabled() -> bool:
    import switches
    return switches.get("AEGIS_FACTS_CACHE", "0") == "1"


def _path() -> Path:
    import switches
    d = switches.get("AEGIS_FACTS_CACHE_DIR")
    return (Path(d) if d else Path.home() / ".aegis" / "cache") / "facts.sqlite"


def _db():
    global _conn
    if _conn is None:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        _conn = sqlite3.connect(str(p), timeout=5, isolation_level=None, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("CREATE TABLE IF NOT EXISTS facts (k TEXT PRIMARY KEY, v TEXT NOT NULL, used REAL NOT NULL)")
    return _conn


def _analyzer_hash() -> str:
    global _code_hash
    if _code_hash is None:
        h = hashlib.sha256()
        for f in sorted(Path(__file__).parent.glob("*.py")):
            h.update(f.name.encode() + b"\0" + f.read_bytes())
        _code_hash = h.hexdigest()[:16]
    return _code_hash


def key(text: str, rel: str, lang: str, phase: str, ctx) -> str:
    import rule_engine
    limits = {k: v for k, v in ctx.limits.items() if k != "seconds"}
    h = hashlib.sha256()
    for part in (rule_engine.current().fingerprint, _analyzer_hash(), json.dumps(limits, sort_keys=True), lang, phase,
                 rel):
        h.update(str(part).encode() + b"\0")
    h.update(text.encode("utf-8", "surrogatepass"))
    return h.hexdigest()


def get(k: str) -> dict | None:
    try:
        row = _db().execute("SELECT v FROM facts WHERE k=?", (k,)).fetchone()
        if row is None:
            return None
        _db().execute("UPDATE facts SET used=? WHERE k=?", (time.time(), k))
        v = json.loads(row[0])
        return v if isinstance(v, dict) else None
    except (sqlite3.Error, ValueError, OSError):
        return None


def put(k: str, entry: dict) -> None:
    try:
        db = _db()
        db.execute("INSERT OR REPLACE INTO facts (k, v, used) VALUES (?, ?, ?)", (k, json.dumps(entry), time.time()))
        if hash(k) % 512 == 0:                               # now and then: keep the table bounded
            n = db.execute("SELECT COUNT(*) FROM facts").fetchone()[0]
            if n > MAX_ROWS:
                db.execute("DELETE FROM facts WHERE k IN (SELECT k FROM facts ORDER BY used LIMIT ?)", (n - MAX_ROWS,))
    except (sqlite3.Error, OSError):
        pass


class Recorder:
    """What one file's analysis adds to the Context, and whether it depended on anything but the file."""

    def __init__(self, ctx, rel: str):
        self.ctx, self.rel = ctx, rel
        self.facts0 = set(ctx.facts)
        self.down0, self.exe0 = set(ctx.downloaded), set(ctx.executable)
        self.na0 = len(ctx.not_analyzed)
        ctx.impure = False

    def entry(self) -> dict | None:
        ctx = self.ctx
        if ctx.impure:
            return None
        facts = []
        for fk in ctx.facts:
            if fk in self.facts0:
                continue
            finding, phase, file, line = fk
            if file != self.rel:
                return None                                   # facts about another file: not this file's alone
            facts.append([finding, phase, line, ctx.facts[fk]])
        return {"facts": facts, "down": sorted(ctx.downloaded - self.down0), "exe": sorted(ctx.executable - self.exe0),
                "na": [list(x) for x in ctx.not_analyzed[self.na0:]]}


def replay(ctx, rel: str, entry: dict) -> None:
    for finding, phase, line, detail in entry.get("facts", ()):
        key = (finding, phase, rel, int(line or 0))
        if key not in ctx.facts:
            ctx.facts[key] = detail
    ctx.downloaded.update(entry.get("down", ()))
    ctx.executable.update(entry.get("exe", ()))
    ctx.not_analyzed.extend(tuple(x) for x in entry.get("na", ()))
