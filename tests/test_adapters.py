"""Offline tests for the tool-dependent / tool-independent split (run: python3 tests/test_adapters.py).

1) the core modules contain no Claude Code specifics (no adapter import by name, no CLAUDE_* variable, no .claude path)
2) the same core answers through two adapters: Claude Code keeps "ask"; Codex, whose hook cannot ask, gets "deny"
3) every agent's settings are protected whichever agent runs the guard (2026-10-23; before: each agent only its own) -
   an agent under one tool that rewrites another tool's settings can switch off that tool's guard or add hooks
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(IMPL))

CORE = ["guard_core.py", "guard_paths.py", "install_parse.py", "scan_engine.py", "remote_wheel.py", "safe_extract.py",
        "artifact_select.py", "collect.py", "integrity.py", "mcp_guard.py", "mode.py", "hook_runtime.py", "env_profile.py", "project_code.py", "attack_path.py",
        # 2026-10-23: the extension checks read every agent's formats from agent_formats.json, never name one
        "agent_config.py", "mcp_scan.py", "hook_scan.py", "plugin_scan.py", "npm_parse.py", "index_config.py"]


def code_strings(tree):
    """String constants that are not docstrings."""
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docs.add(id(first.value))
    return [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]


# 1) no Claude Code specifics in the core
for rel in CORE:
    tree = ast.parse((IMPL / rel).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            names = [a.name for a in node.names]
            assert "claude_code" not in mod and "claude_code" not in names, (rel, mod, names)
        if isinstance(node, ast.Import):
            assert not any("claude_code" in a.name for a in node.names), rel
    for s in code_strings(tree):
        assert "CLAUDE_" not in s and ".claude/" not in s and "hookSpecificOutput" not in s, (rel, s[:80])
# guard_paths keeps the old Claude lists only as compatibility constants; the functions take them from the adapter
import guard_paths  # noqa: E402
from adapters import claude_code, codex  # noqa: E402
assert guard_paths.file_path_is_protected("/p/.claude/settings.json")                       # default adapter: Claude Code
assert guard_paths.file_path_is_protected("/p/.codex/hooks.json", codex)
assert guard_paths.file_path_is_protected("/p/.claude/settings.json", codex)                # 3) every agent's settings
assert guard_paths.file_path_is_protected("/p/.codex/hooks.json", claude_code)
assert guard_paths.file_path_is_protected("/x/aegis-pilot/scan_engine.py", codex)   # the guard's own files: always


def run(script: str, event: dict, patch: str = ""):
    code = f"""
import sys, runpy
sys.path.insert(0, {str(IMPL)!r})
{patch}
runpy.run_path({str(IMPL / 'hooks' / script)!r}, run_name="__main__")
"""
    r = subprocess.run([sys.executable, "-c", code], input=json.dumps(event), capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AEGIS_MODE": "user"})
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None


with tempfile.TemporaryDirectory() as d:
    # 2) the same finding (a shell write to the agent's hook config) through both adapters, in user mode (a person asked;
    #    auto mode answers both with a refusal card - tests/test_auto_events.py)
    out = run("pretooluse_check.py", {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "echo x >> .claude/settings.json"}})
    assert out and out["permissionDecision"] == "ask", out
    out = run("codex_pretooluse.py", {"tool_name": "Bash", "cwd": d, "hook_event_name": "PreToolUse",
                                      "tool_input": {"command": "echo x >> .codex/hooks.json"}})
    assert out and out["permissionDecision"] == "deny" and out["permissionDecisionReason"].startswith("[AegisPilot"), out
    assert not re.search(r"Approving|If (?:you )?approved?", out["permissionDecisionReason"]) and "cannot ask a person" in out["permissionDecisionReason"], out
    # 3) every agent's settings are protected whichever agent runs the guard (not only its own):
    #    Codex cannot ask, so its write to Claude Code's settings is refused; Claude Code asks about Codex's hooks
    assert run("codex_pretooluse.py", {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "echo x >> .claude/settings.json"}})["permissionDecision"] == "deny"
    assert run("pretooluse_check.py", {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "echo x >> .codex/hooks.json"}})["permissionDecision"] == "ask"
    # Codex file edits arrive as apply_patch; every patched file is checked
    patch = "*** Begin Patch\n*** Update File: src/app.py\n@@\n-a\n+b\n*** Update File: .codex/config.toml\n@@\n-a\n+b\n*** End Patch"
    out = run("codex_pretooluse.py", {"tool_name": "apply_patch", "cwd": d, "tool_input": {"command": patch}})
    assert out and out["permissionDecision"] == "deny", out
    assert run("codex_pretooluse.py", {"tool_name": "apply_patch", "cwd": d,
                                       "tool_input": {"command": "*** Begin Patch\n*** Add File: README.md\n+hi\n*** End Patch"}}) is None
    # not an install, no protected path: silent on both
    assert run("codex_pretooluse.py", {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "ls -la"}}) is None
    # the error net answers in the agent's format too: Codex gets deny, never an ask it would ignore
    crash = "import scan_engine; scan_engine.scan_packages = lambda *a, **k: (_ for _ in ()).throw(RuntimeError('bug'))"
    out = run("codex_pretooluse.py", {"tool_name": "Bash", "cwd": d, "tool_input": {"command": "pip install requests"}}, crash)
    assert out and out["permissionDecision"] == "deny" and "RuntimeError" in out["permissionDecisionReason"], out

print("adapters: all cases passed")
