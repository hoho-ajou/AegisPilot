"""
AegisPilot - auto mode: the agent decides, the guard gives it the evidence first.

A hook can only allow, refuse or ask before the tool runs; an allowed command has already run by the time the agent could
read anything. So for the agent to decide BEFORE it runs, the guard refuses once and hands over the evidence with an ack
id. The agent then either takes another way (another version, another package, no change at all - checked again as
usual) or goes on with this exact action:

  python3 -I <guard>/guard_cli.py ack <id>     # the agent's decision, recorded
  <the same command / the same file write>      # passes once

An ack is for one action: the fingerprint of the refused tool call (the command text, or the file and its new content),
used once, within ACK_TTL_SECONDS. A changed command is a new action and is checked again. Nothing here decides for the
agent; it only keeps "decided" bound to what was shown. The file lives in ~/.aasm/ (a protected path for the agent's
own writes); user mode never uses it (a person answers the approval window instead).
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from pathlib import Path

ACK_TTL_SECONDS = 30 * 60
KEEP_SECONDS = 24 * 3600          # issued / used entries kept for the record, then dropped


def state_file() -> Path:
    return Path.home() / ".aasm" / "acks.json"


def fingerprint(kind: str, project_dir, *parts) -> str:
    h = hashlib.sha256()
    for p in (kind, str(Path(project_dir).resolve()) if project_dir else "", *parts):
        h.update(str(p if p is not None else "").encode("utf-8", "replace") + b"\0")
    return h.hexdigest()


class _Locked:
    """The state file read and written under an exclusive lock (parallel hooks)."""

    def __enter__(self):
        path = state_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.fd = os.open(path.with_suffix(".lock"), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            import fcntl
            fcntl.flock(self.fd, fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        try:
            doc = json.loads(path.read_text())
            self.doc = doc if isinstance(doc, dict) else {}
        except (OSError, ValueError):
            self.doc = {}
        self.before = json.dumps(self.doc, sort_keys=True)
        return self.doc

    def __exit__(self, *exc):
        now = time.time()
        doc = {k: v for k, v in self.doc.items() if isinstance(v, dict) and now - v.get("issued", 0) < KEEP_SECONDS}
        path = state_file()
        try:
            if json.dumps(doc, sort_keys=True) != self.before:
                tmp = path.with_suffix(f".{os.getpid()}.tmp")
                tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=1))
                os.replace(tmp, path)
        finally:
            os.close(self.fd)
        return False


def issue(fp: str, summary: str = "") -> str:
    """A new ack id for the refused action `fp`."""
    ack_id = secrets.token_hex(4)
    with _Locked() as doc:
        doc[ack_id] = {"fp": fp, "issued": time.time(), "summary": summary[:200]}
    return ack_id


def grant(ack_id: str) -> tuple[bool, str]:
    """The agent's decision to go on: (ok, message)."""
    with _Locked() as doc:
        e = doc.get(ack_id)
        if not isinstance(e, dict):
            return False, "No such ack id. Use the exact id the guard gave you."
        if e.get("used"):
            return False, "This ack id was already used. To do the same action again, run the command again to get a new id."
        if time.time() - e.get("issued", 0) > ACK_TTL_SECONDS:
            return False, "This ack id has expired. Run the command again to get a new id."
        e["granted"] = time.time()
    return True, "Acknowledged. Run the same command (or the same file change) once more, unchanged, and it will go through."


def consume(fp: str) -> dict | None:
    """The granted, unused, unexpired ack for `fp` (now marked used), or None."""
    now = time.time()
    with _Locked() as doc:
        for ack_id, e in doc.items():
            if (isinstance(e, dict) and e.get("fp") == fp and e.get("granted") and not e.get("used")
                    and now - e.get("issued", 0) <= ACK_TTL_SECONDS):
                e["used"] = now
                return {"id": ack_id, **e}
    return None
