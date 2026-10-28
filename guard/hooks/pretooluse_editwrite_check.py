#!/usr/bin/env python3
"""
AegisPilot - PreToolUse hook on Edit|MultiEdit|Write for Claude Code.

Two independent checks, both "confirm" (Claude Code "ask", not a silent deny) since both need a human to look:
  - MCP config: the file is an MCP config (.mcp.json / ~/.claude.json) -> new server entries not on the known-source
        allowlist are flagged (diffed against the stored snapshot, judged on the text AFTER the edit).
  - protected path: the file is a protected guard path (settings.json, hook scripts, the guard itself) edited directly,
        bypassing Bash entirely.
  - package index configs (pip.conf, uv.toml, pyproject.toml, Pipfile): a non-PyPI source added by the edit.
  - hooks: commands added to a settings file, or code written into a hooks folder, are scanned (hook_scan.py).

This file only connects Claude Code to the guard: adapters/claude_code.py reads the event (and derives the file's text
after the edit) and writes the answer, guard_core.check_file_write decides (tool-independent).
"""
import os
import sys

# The guard folder goes AFTER the standard library and before site-packages: first on the path, a file
# named like a standard module (json.py) planted next to the guard would be imported instead of it. Only sys and os
# (loaded by Python at start) are used before this line.
_GUARD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) not in (_GUARD, os.path.join(_GUARD, "hooks"))]
sys.path.insert(next((i for i, p in enumerate(sys.path) if p.endswith(("site-packages", "dist-packages"))), len(sys.path)), _GUARD)

from pathlib import Path

import hook_runtime  # noqa: E402
from adapters import claude_code as agent  # noqa: E402


def relevant(event: dict) -> bool:
    """Should a guard failure on this event be surfaced? Only for the files this hook watches."""
    from guard_core import file_is_relevant
    got = agent.file_write(event, with_text=False)
    return bool(got) and file_is_relevant(got[0], agent)


def main(event: dict) -> None:
    got = agent.file_write(event, with_text=False)
    if not got:
        return
    from guard_core import ALLOW, check_file_write
    from guard_paths import file_path_is_mcp_config, file_path_is_protected
    from index_config import is_watched_file
    file_path, _, project_dir = got
    wants_text = file_path_is_mcp_config(file_path, agent) or is_watched_file(file_path) or file_path_is_protected(file_path, agent)
    text = agent.file_write(event)[1] if wants_text else None
    decision = check_file_write(file_path, text, project_dir, agent)
    if decision.action != ALLOW:
        hook_runtime.emit(decision.action, decision.reason)


if __name__ == "__main__":
    hook_runtime.run(main, relevant, "Edit|Write hook", agent)
