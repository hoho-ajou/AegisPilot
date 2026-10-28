#!/usr/bin/env python3
"""
AegisPilot - PreToolUse hook on Bash for Claude Code.

Wire this into .claude/settings.json as a PreToolUse hook on the Bash tool (guard_cli.py snippet prints the block).
This file only connects Claude Code to the guard: adapters/claude_code.py reads the event and writes the answer,
guard_core.check_command decides (tool-independent), hook_runtime adds the deadline and the error net.

The guard only *inspects* the command; it never rewrites it. Not an install command and no protected path -> no output,
so unrelated commands are never blocked.
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
    """Should a guard failure on this event be surfaced (instead of silently passing)?"""
    from guard_core import command_is_relevant
    got = agent.shell_command(event)
    return bool(got) and command_is_relevant(got[0], agent)


def main(event: dict) -> None:
    got = agent.shell_command(event)
    if not got:
        return
    from guard_core import ALLOW, check_command
    decision = check_command(got[0], got[1], agent, actor={k: event.get(k) for k in ("session_id", "agent_id") if event.get(k)})
    if decision.action == ALLOW:
        return                          # fall through silently (no stdout): the command proceeds normally
    if decision.detail:                 # stdout is reserved for the hook JSON, so the person-facing report goes to stderr
        print("", file=sys.stderr)
        print(decision.detail, file=sys.stderr)
        print("", file=sys.stderr)
        sys.stderr.flush()
    hook_runtime.emit(decision.action, decision.reason)


if __name__ == "__main__":
    hook_runtime.run(main, relevant, "install check", agent)
