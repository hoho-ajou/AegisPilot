"""
AegisPilot - agent adapters: everything that depends on WHICH coding agent runs the guard.

The guard is split in two:
  tool-independent   install_parse, scan_engine (+ remote_wheel, safe_extract, artifact_select, collect, ml_bridge),
                     review_report, r4/, mode, integrity, mcp_guard, guard_paths, guard_core
                     -> takes a command / a file path + text and returns a Decision(action, reason, detail)
  tool-dependent     this package + hooks/  -> reads the agent's hook event, answers in the agent's format,
                     names the agent's own config files and how its session surface is detected

An adapter is a module with these names (claude_code.py is the reference):
  NAME                  short id, e.g. "claude-code"
  SUPPORTS_CONFIRM      can the agent's hook ask a person (Claude Code "ask")? If not, CONFIRM is answered as a refusal
  CONFIG_FRAGMENTS      path fragments of the agent's own settings/hooks; writing them could switch the guard off
  MCP_CONFIG_NAMES      file names of the agent's MCP server configs (the formats of every known agent's MCP servers,
                        hooks and plugins are data in agent_formats.json, read by agent_config.py - not per adapter)
  detect_surface(env)   {"surface": terminal|app|api|unknown, "width": columns, ...}
  shell_command(event)  (command, project_dir) if the event is a shell command about to run, else None
  file_write(event)     (file_path, proposed_text_or_None, project_dir) if the event writes a file, else None
  answer(action, reason) the text the hook prints to stdout for a core action ("allow" -> None = print nothing)
"""
from __future__ import annotations

from . import claude_code

DEFAULT = claude_code


def all_adapters() -> list:
    """Every adapter the guard has. Their settings are protected whichever agent runs the guard: an agent under Claude
    Code that rewrites ~/.codex/config.toml can switch off the guard (or add hooks) in Codex."""
    from . import codex
    return [claude_code, codex]


def get(name: str | None = None):
    """The adapter for `name`; the Claude Code adapter when no name is given."""
    if not name or name == claude_code.NAME:
        return claude_code
    if name == "codex":
        from . import codex
        return codex
    raise ValueError(f"unknown agent adapter: {name}")
