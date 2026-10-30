"""
AegisPilot - which package indexes the person chose, and which the agent brought in.

The guard scans what PyPI / npmjs serve. An install from another index cannot be scanned, but that is only a threat when
the index is not one the organisation chose: a company mirror set up by a person is trusted like PyPI, an index the
agent brought in (from a README, an issue, a web page) is not. The guard cannot ask who wrote a config file, but it
sees every change the agent makes through its tools - so it records those, and trusts the rest:

  agent      an index the agent added: `pip config set ... URL`, an Edit/Write of pip.conf / uv.toml / .npmrc ...,
             or a shell write to such a file (URL unknown -> "pending": the next new index found in a config is it)
  trusted    an index found in a config file or in the session's environment (set before the agent ran) that the agent
             did not add - the person's own setting; first seen is recorded

An install reads where it would fetch from (index_config.findings, .npmrc, flags, variables):
  config / session environment   trusted -> scanned as nothing to flag; agent-added -> the agent decides (card)
  the command itself (-i, --registry, PIP_INDEX_URL=... in the command, a requirements file's -i line)
                                  the agent chose it -> card, unless it is an index the person already uses

State: ~/.aegis/indexes.json (a protected path for the agent's own writes). Things the guard does not see (a script that
writes pip.conf) land in "trusted" - the same limit as every other bypass of the hook.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

_URL = re.compile(r"https?://[^\s'\"<>]+")


def state_file() -> Path:
    return Path.home() / ".aegis" / "indexes.json"


def norm(url: str) -> str:
    u = url.strip().strip("'\"").rstrip("/")
    m = re.match(r"^(https?://)([^/]+)(.*)$", u, re.I)
    return (m.group(1).lower() + m.group(2).lower() + m.group(3)) if m else u


def urls_in(text: str) -> list[str]:
    return [norm(u) for u in _URL.findall(text or "")]


def _load() -> dict:
    try:
        doc = json.loads(state_file().read_text())
        if isinstance(doc, dict):
            return {"trusted": dict(doc.get("trusted") or {}), "agent": dict(doc.get("agent") or {}),
                    "pending": doc.get("pending")}
    except (OSError, ValueError):
        pass
    return {"trusted": {}, "agent": {}, "pending": None}


def _save(doc: dict) -> None:
    path = state_file()
    try:
        import safe_write
        safe_write.write_text(path.parent, path.name, json.dumps(doc, ensure_ascii=False, indent=1))
    except OSError:
        pass


def record_agent_change(urls: list[str] | None) -> None:
    """The agent is changing where installs come from. urls None = the new value is not known (a shell write)."""
    doc = _load()
    now = time.time()
    if urls:
        for u in urls:
            doc["agent"][norm(u)] = now
            doc["trusted"].pop(norm(u), None)
    else:
        doc["pending"] = now
    _save(doc)


def filter_unscanned(items: list[dict]) -> tuple[list[dict], list[str]]:
    """(the unscanned items left after dropping indexes the person chose, those trusted indexes). Items carry "url" and
    "origin" ("config" / "session_env" / "command"); anything else is kept as it is."""
    if not any(i.get("kind") == "custom_index" and i.get("url") for i in items):
        return items, []
    doc, changed, out, trusted = _load(), False, [], []
    for item in items:
        url = norm(item["url"]) if item.get("kind") == "custom_index" and item.get("url") else None
        if url is None:
            out.append(item)
            continue
        if url in doc["agent"]:
            out.append(dict(item, reason="index added by the agent (not set by a person) - " + item.get("reason", "")))
            continue
        if url in doc["trusted"]:
            trusted.append(url)
            continue
        if item.get("origin") in ("config", "session_env"):
            if doc["pending"]:
                doc["agent"][url], doc["pending"], changed = time.time(), None, True
                out.append(dict(item, reason="index the agent added to a config file - " + item.get("reason", "")))
            else:
                doc["trusted"][url], changed = time.time(), True          # the person's own setting
                trusted.append(url)
            continue
        out.append(item)                                                  # chosen in the command, not one in use
    if changed:
        _save(doc)
    return out, trusted
