#!/usr/bin/env python3
"""
AegisPilot - PreToolUse hook for Codex CLI (see adapters/codex.py).

One hook for both tools Codex routes through PreToolUse that matter here: "Bash" (install commands, shell writes to
protected paths) and "apply_patch" (file edits; every patched file is checked). Same core as the Claude Code hooks
(guard_core); only the event reading and the answer format differ, and Codex cannot ask a person, so a CONFIRM is sent
as a refusal with the reason.

<repo>/.codex/hooks.json (matcher is a regex on tool_name):
  {"hooks": {"PreToolUse": [{"matcher": "^(Bash|apply_patch)$",
     "hooks": [{"type": "command", "command": "python3 /ABS/PATH/guard/hooks/codex_pretooluse.py", "timeout": 600}]}]}}
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
from adapters import codex as agent  # noqa: E402


def relevant(event: dict) -> bool:
    from guard_core import command_is_relevant, file_is_relevant
    got = agent.shell_command(event)
    if got:
        return command_is_relevant(got[0], agent)
    return any(file_is_relevant(f, agent) for f in agent.patched_files(event))


def main(event: dict) -> None:
    from guard_core import ALLOW, check_command, check_file_write
    got = agent.shell_command(event)
    if got:
        decision = check_command(got[0], got[1], agent, actor={k: event.get(k) for k in ("session_id", "agent_id") if event.get(k)})
        if decision.action != ALLOW:
            if decision.detail:
                print(decision.detail, file=sys.stderr)
            hook_runtime.emit(decision.action, decision.reason)
        return
    project_dir = event.get("cwd") or "."
    for file_path in agent.patched_files(event):
        decision = check_file_write(file_path, None, project_dir, agent)
        if decision.action != ALLOW:
            hook_runtime.emit(decision.action, decision.reason)
            return


if __name__ == "__main__":
    hook_runtime.run(main, relevant, "Codex hook", agent)
