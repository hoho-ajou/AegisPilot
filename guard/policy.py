"""
AegisPilot - policy stage: allow / deny lists that people maintain.

Two files, read on every install decision:
  system   /etc/aasm/policy.json (or AASM_SYSTEM_POLICY): meant to be owned by root, so the agent - running as the
           developer - can read it but not write it. This is the enforced layer.
  project  <project>/.aasm/policy.json: a protected path (an agent edit asks the person first), the same file that holds
           "mode". Convenient, but only as strong as that check.

  {"deny":  [{"package": "leftpad", "versions": "*", "reason": "...", "approver": "..."}],
   "allow": [{"package": "corp-utils", "version": "1.4.2", "reason": "internal service", "approver": "...", "expires": "2026-12-31"}]}

Rules (kept deliberately one-way):
  - deny matches by name (and "versions": "*" or a list of exact versions): the package is BLOCKed whatever the scan says.
  - allow needs the exact name AND version, must not be expired, and can only turn a REVIEW into ALLOW. It never lowers a
    BLOCK (critical vulnerabilities, download-and-execute, ...): a list entry is a person's earlier judgement about that
    exact release, not a reason to install something the guard found dangerous.
  - system entries win over project entries; deny wins over allow.
The decision and its source are written into the record ("policy"), so reports show who allowed or denied what.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

import switches  # noqa: E402
SYSTEM_POLICY = Path(switches.get("AASM_SYSTEM_POLICY") or "/etc/aasm/policy.json")   # a built guard: system config only


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _load(path: Path, source: str) -> tuple[list, list, list[str]]:
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        return [], [], []
    except (OSError, ValueError) as e:
        return [], [], [f"could not read the {source} policy file ({type(e).__name__}): deciding without lists"]
    if not isinstance(doc, dict):
        return [], [], [f"{source} policy file has an invalid format"]
    tag = lambda items: [dict(x, source=source) for x in items if isinstance(x, dict) and x.get("package")] if isinstance(items, list) else []
    return tag(doc.get("deny")), tag(doc.get("allow")), []


def load(project_dir) -> dict:
    deny, allow, notes = [], [], []
    for path, source in ((SYSTEM_POLICY, "system"), (Path(project_dir) / ".aasm" / "policy.json", "project")):
        d, a, n = _load(path, source)
        deny += d; allow += a; notes += n
    return {"deny": deny, "allow": allow, "notes": notes}


def _expired(entry: dict, today: str) -> bool:
    exp = str(entry.get("expires") or "")
    return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", exp)) and exp < today


def decide(pol: dict, name: str, version: str | None, verdict: str, today: str | None = None) -> tuple[str, dict | None]:
    """(new verdict, policy note or None)."""
    today = today or time.strftime("%Y-%m-%d")
    n, v = _norm(name), str(version or "")
    for e in pol["deny"]:
        versions = e.get("versions", "*")
        if _norm(e["package"]) == n and (versions == "*" or (isinstance(versions, list) and v in map(str, versions))):
            return "BLOCK", {"action": "deny", "source": e["source"], "reason": str(e.get("reason", ""))[:200],
                             "approver": str(e.get("approver", ""))[:80]}
    for e in pol["allow"]:
        if _norm(e["package"]) != n or str(e.get("version", "")) != v or not v:
            continue
        info = {"source": e["source"], "reason": str(e.get("reason", ""))[:200], "approver": str(e.get("approver", ""))[:80],
                "expires": e.get("expires")}
        if _expired(e, today):
            return verdict, {"action": "allow_expired", **info}
        if verdict == "BLOCK":
            return verdict, {"action": "allow_ignored", **info}       # never lowers a BLOCK
        return "ALLOW", {"action": "allow", **info}
    return verdict, None
