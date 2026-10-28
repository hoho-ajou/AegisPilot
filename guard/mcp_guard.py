"""
AegisPilot - untrusted/unknown MCP server registration guard.

Context (verified against Claude Code docs this session): interactive
sessions already get an approval prompt before a project-scoped MCP server's
first use, but non-interactive sessions (SDK/-p/cloud) load it without
prompting. This module closes the gap for the interactive case too, at the
point of *registration* (an Edit/Write to .mcp.json / ~/.claude.json),
instead of relying only on Claude Code's own first-use prompt.

A snapshot of the last-seen config is kept locally so only *new* server
entries are flagged - not ones already reviewed in a previous checkpoint.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

GUARD_DIR = Path(__file__).resolve().parent
# the servers seen so far, per config file. Not in the guard folder (2026-10-23): a file the guard writes there at run
# time showed up as "added after the build" in the integrity check, and a system install's folder is not writable.
SNAPSHOT_PATH = Path.home() / ".aasm" / "mcp_snapshot.json"

# starting allowlist: well-known, officially-published MCP servers. Empty-ish
# on purpose for V1 - the point isn't to pre-approve everything plausible,
# it's to flag anything NOT on this short, deliberately curated list so a
# human looks at it once. Grows over time as the team reviews real servers.
KNOWN_SOURCE_PREFIXES = [
    "@modelcontextprotocol/server-",
    "@anthropic-ai/",
]


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _server_entries(config: dict[str, Any]) -> dict[str, Any]:
    return config.get("mcpServers", {})


def _read(path: Path) -> str | None:
    try:
        return path.read_text()
    except OSError:
        return None


def servers_in(file_path: str, text: str | None) -> dict[str, Any]:
    """{name: entry} of the MCP servers in a config file of any known agent (agent_config / agent_formats.json: JSON
    mcpServers, VS Code's servers, Codex's TOML [mcp_servers], ~/.claude.json's per-project servers). A file no agent
    format names falls back to top-level mcpServers."""
    import agent_config
    specs = [s for _, kind, s in agent_config.specs_for(file_path) if kind == "mcp"]
    if not specs:
        try:
            return _server_entries(json.loads(text)) if text else {}
        except (ValueError, AttributeError):
            return {}
    out: dict[str, Any] = {}
    for spec in specs:
        doc = agent_config.parse(text, spec["format"])
        if doc:
            out.update(agent_config.mcp_servers(doc, spec))
    return out


def _server_source(entry: dict[str, Any]) -> str:
    """The string we check against the allowlist / scan for risk signals."""
    if "command" in entry:
        return " ".join([str(entry.get("command", ""))] + [str(a) for a in entry.get("args", []) if isinstance(a, (str, int, float))])
    return str(entry.get("url") or entry.get("httpUrl") or entry.get("serverUrl") or "")


def _is_known_source(source: str) -> bool:
    # source is "command arg1 arg2 ..." (e.g. "npx @modelcontextprotocol/server-filesystem")
    # or a bare url - check each token, not the joined string, since a known
    # package name is rarely the first token (npx/uvx/python -m usually is).
    # Found via testing: the joined-string startswith() never matched because
    # "npx " always came first.
    tokens = source.split()
    return any(tok.startswith(prefix) for tok in tokens for prefix in KNOWN_SOURCE_PREFIXES)


def check_new_mcp_servers(file_path: str, proposed_text: str | None = None) -> list[dict[str, Any]]:
    """Returns {name, source, known} for server entries that are new.

    The hook runs BEFORE the edit is applied, so the file on disk does not yet
    contain what is being added: pass the edit's resulting text as
    `proposed_text` and that is what gets judged. (Measured 2026-10-04: judging
    only the on-disk file surfaced a newly written server one edit too late.)

    Baseline = servers the previous checkpoint saw + servers on disk right now,
    so anything already present (or approved earlier) is not re-flagged. The
    snapshot is updated to that baseline only - never to the proposed content -
    so a proposal the human rejects is flagged again if it comes back.
    """
    disk_servers = servers_in(file_path, _read(Path(file_path)))
    snapshot = _load_json(SNAPSHOT_PATH)
    baseline = dict(snapshot.get(file_path, {}))
    baseline.update(disk_servers)

    if proposed_text is None:
        current_servers = disk_servers
    else:
        current_servers = servers_in(file_path, proposed_text)    # {} when not readable yet (partial edit)

    new_entries = []
    for name, entry in current_servers.items():
        if name in baseline:
            continue
        source = _server_source(entry)
        from mcp_scan import launch_command
        new_entries.append({
            "name": name,
            "source": source,
            "known": _is_known_source(source),
            "launch": launch_command(entry),        # None for a remote server: nothing local to scan
        })

    snapshot[file_path] = baseline
    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2, ensure_ascii=False))

    return new_entries
