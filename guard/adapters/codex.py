"""
AegisPilot - Codex CLI adapter (written from the official hook docs; run once per case with real
codex-cli 0.162.0 on 2026-10-13: install refused -> requirements fixed -> installed, .codex/hooks.json write refused).

Codex PreToolUse hook contract (https://learn.chatgpt.com/docs/hooks.md, read 2026-10-13):
  - stdin: {"cwd", "hook_event_name": "PreToolUse", "tool_name", "tool_input", "session_id", "model", ...}
           shell commands: tool_name "Bash", tool_input.command; file edits: tool_name "apply_patch", the patch text in
           tool_input.command ("*** Add File: <path>" / "*** Update File: <path>" / "*** Delete File: <path>")
  - stdout: {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "..."}}; plain text on stdout is ignored
  - "ask" is "parsed but not supported yet": Codex marks the hook as failed and RUNS the tool call. So this adapter
    never answers "ask" - a CONFIRM becomes a refusal with the same reason (SUPPORTS_CONFIRM = False).
  - hooks live in ~/.codex/hooks.json, <repo>/.codex/hooks.json or [hooks] in config.toml; project hooks need the
    project trusted, and non-managed hooks must be reviewed (/hooks) before they run. Default timeout 600 s.
  - the docs: "Treat tool hooks as a useful guardrail, not a complete enforcement boundary."

Codex's extension formats (config.toml [mcp_servers] / [plugins], hooks.json, `codex mcp add`) are data in
agent_formats.json and read by agent_config.py, so they are checked whichever agent edits them. Codex's
own edits arrive as apply_patch without the resulting text: config.toml is then a protected path (refusal with the
reason), the MCP / hook / plugin scan needs the text and does not run.
Surface: no documented environment marker was checked, so it reports "unknown" (default width).
"""
from __future__ import annotations

import json
import os
import re

NAME = "codex"
SUPPORTS_CONFIRM = False
CONFIG_FRAGMENTS = [".codex/config.toml", ".codex/hooks.json", ".codex/hooks/"]
MCP_CONFIG_NAMES: tuple[str, ...] = ()
CONFIG_ENV_VARS = ("CODEX_HOME",)                 # moves the config folder (hooks.json, config.toml)
_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+?)\s*$", re.M)
_PATCH_MOVE = re.compile(r"^\*\*\* Move to: (.+?)\s*$", re.M)


def detect_surface(env=None) -> dict:
    env = os.environ if env is None else env
    try:
        cols = int(env.get("COLUMNS", ""))
    except (TypeError, ValueError):
        cols = None
    width = max(40, min(100, cols)) if cols else 60
    return {"surface": "unknown", "entrypoint": "codex", "attended": None, "columns": cols, "width": width}


def _command_text(tool_input) -> str:
    cmd = (tool_input or {}).get("command", "") if isinstance(tool_input, dict) else ""
    if isinstance(cmd, list):                      # defensive: an argv list instead of a string
        cmd = " ".join(str(c) for c in cmd)
    return cmd if isinstance(cmd, str) else ""


def shell_command(event: dict):
    if event.get("tool_name") != "Bash":
        return None
    return _command_text(event.get("tool_input")), event.get("cwd") or os.getcwd()


def patched_files(event: dict) -> list[str]:
    """Every path an apply_patch call adds, updates, deletes or moves to."""
    if event.get("tool_name") != "apply_patch":
        return []
    patch = _command_text(event.get("tool_input"))
    return _PATCH_FILE.findall(patch) + _PATCH_MOVE.findall(patch)


def file_write(event: dict, with_text: bool = True):
    """The first patched file (a patch can touch several: hooks/codex_pretooluse.py checks them all via patched_files).
    The text after the patch is not derived (None)."""
    files = patched_files(event)
    return (files[0], None, event.get("cwd") or os.getcwd()) if files else None


def answer(action: str, reason: str) -> str | None:
    if action not in ("confirm", "refuse", "ask", "deny"):
        return None
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}, ensure_ascii=False)
