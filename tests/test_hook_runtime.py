"""Offline tests for hook_runtime: the hook's own deadline and error handling
(run: python3 tests/test_hook_runtime.py).

Claude Code discards the output of a PreToolUse hook that hits its timeout and lets the tool call
proceed; an uncaught exception (exit 1) does not block either. These tests pin down what the guard
does about it itself: answer "ask" before the deadline, and turn internal errors into "ask" - but only
for events it is responsible for.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(IMPL))


def run_hook(script: str, event: dict, patch: str, env: dict | None = None):
    code = f"""
import sys, runpy
sys.path.insert(0, {str(IMPL)!r}); sys.path.insert(0, {str(IMPL / 'hooks')!r})
{patch}
runpy.run_path({str(IMPL / 'hooks' / script)!r}, run_name="__main__")
"""
    import os
    t = time.time()
    r = subprocess.run([sys.executable, "-c", code], input=json.dumps(event), capture_output=True, text=True,
                       env={**os.environ, **(env or {})}, timeout=60)
    out = json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None
    return r.returncode, out, time.time() - t


INSTALL = {"tool_name": "Bash", "cwd": "/tmp", "tool_input": {"command": "pip install requests"}}
CRASH = "import scan_engine; scan_engine.scan_packages = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('bug'))"
HANG = "import scan_engine, time; scan_engine.scan_packages = lambda *a, **k: time.sleep(30)"

# 1) internal error while scanning an install: no silent pass - an explicit ask, exit 0
code, out, _ = run_hook("pretooluse_check.py", INSTALL, CRASH)
assert code == 0 and out and out["permissionDecision"] == "ask" and "RuntimeError" in out["permissionDecisionReason"], (code, out)
assert out["permissionDecisionReason"].startswith("[AegisPilot]") and len(out["permissionDecisionReason"]) <= 200

# 2) the same bug on an unrelated command stays silent (a bug must not turn every `ls` into a popup)
code, out, _ = run_hook("pretooluse_check.py", {"tool_name": "Bash", "cwd": "/tmp", "tool_input": {"command": "ls -la"}},
                        "import install_parse; install_parse.parse_install_command = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('bug'))")
assert code == 0 and out is None, (code, out)

# 3) a scan that cannot finish: the guard answers before the harness would cancel it, instead of hanging
code, out, secs = run_hook("pretooluse_check.py", INSTALL, HANG, {"AEGIS_HOOK_DEADLINE_SECONDS": "1"})
assert code == 0 and out and out["permissionDecision"] == "ask" and "did not finish within" in out["permissionDecisionReason"], (code, out)
assert secs < 10, secs

# 4) Edit|Write hook: same net for the files it watches, silent for others
EDIT = {"tool_name": "Edit", "cwd": "/tmp", "tool_input": {"file_path": "/p/.claude/settings.json", "old_string": "a", "new_string": "b"}}
BREAK = "import review_report; review_report.write_report = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('bug'))"
code, out, _ = run_hook("pretooluse_editwrite_check.py", EDIT, BREAK)
assert code == 0 and out and out["permissionDecision"] == "ask" and "Internal guard error" in out["permissionDecisionReason"], (code, out)
code, out, _ = run_hook("pretooluse_editwrite_check.py", {"tool_name": "Write", "cwd": "/tmp", "tool_input": {"file_path": "/p/readme.md", "content": "x"}},
                        "import hook_runtime; hook_runtime.emit = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('bug'))")
assert code == 0 and out is None, (code, out)

# 4b) AEGIS_FAIL_CLOSED=1: the same failures refuse instead of asking (opt-in)
code, out, _ = run_hook("pretooluse_check.py", INSTALL, CRASH, {"AEGIS_FAIL_CLOSED": "1"})
assert code == 0 and out and out["permissionDecision"] == "deny" and "AEGIS_FAIL_CLOSED" in out["permissionDecisionReason"], (code, out)
code, out, _ = run_hook("pretooluse_check.py", INSTALL, HANG, {"AEGIS_HOOK_DEADLINE_SECONDS": "1", "AEGIS_FAIL_CLOSED": "1"})
assert code == 0 and out and out["permissionDecision"] == "deny", (code, out)
code, out, _ = run_hook("pretooluse_check.py", {"tool_name": "Bash", "cwd": "/tmp", "tool_input": {"command": "ls -la"}},
                        "import install_parse; install_parse.parse_install_command = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('bug'))",
                        {"AEGIS_FAIL_CLOSED": "1"})
assert code == 0 and out is None, (code, out)                     # still only for commands the guard is responsible for

# 5) unreadable input still falls through silently, as before
r = subprocess.run([sys.executable, str(IMPL / "hooks" / "pretooluse_check.py")], input="not json", capture_output=True, text=True)
assert r.returncode == 0 and not r.stdout.strip()

# 6) the three time limits must nest: scan budget < the guard's own deadline < the hook timeout in settings
import hook_runtime, scan_engine, guard_cli  # noqa: E402
assert scan_engine.SCAN_BUDGET_SECONDS < hook_runtime.HOOK_DEADLINE_SECONDS < guard_cli.HOOK_TIMEOUT_SECONDS, \
    (scan_engine.SCAN_BUDGET_SECONDS, hook_runtime.HOOK_DEADLINE_SECONDS, guard_cli.HOOK_TIMEOUT_SECONDS)

print("hook_runtime: all cases passed")
