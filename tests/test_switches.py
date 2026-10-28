"""Switches that can only weaken the guard are not taken from the environment by a built guard, only from a settings
file (~/.aasm/config.json, /etc/aasm/config.json - guard/switches.py, 2026-10-23); a development checkout keeps the
environment (the tests use it). run: python3 tests/test_switches.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guard"))
import switches  # noqa: E402

# development checkout: the environment as before
os.environ["AASM_MCP_SCAN"] = "0"
assert not switches.released() and switches.get("AASM_MCP_SCAN", "1") == "0" and switches.ignored() == []
os.environ.pop("AASM_MCP_SCAN")
# a system config that is not root-owned (or is group/world writable) is not trusted
with tempfile.TemporaryDirectory() as t:
    cfg = Path(t, "config.json")
    cfg.write_text(json.dumps({"env": {"AASM_MCP_SCAN": "0"}}))
    assert switches._system_env(cfg) == {}                      # owned by this (non-root) user
    assert switches._user_env(cfg) == {"AASM_MCP_SCAN": "0"}    # the user's own file (this guard folder is writable)

with tempfile.TemporaryDirectory() as t:
    out = Path(t) / "guard"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_dist.py"), "test", "--out", str(out), "--skip-tests"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    weak = {"AASM_MCP_SCAN": "0", "AASM_RULES_DIR": "/tmp/empty-rules", "AASM_HOOK_DEADLINE_SECONDS": "0.001",
            "AASM_SYSTEM_POLICY": "/tmp/allow-everything.json", "AASM_ARTIFACT_POLICY": "sdist_first", "AASM_CACHE": "1"}
    home = Path(t) / "home"
    env = {**os.environ, **weak, "AASM_MODE": "user", "HOME": str(home)}
    code = ("import sys; sys.path.insert(0, %r); import switches; "
            "print({n: switches.get(n) for n in switches.WEAKENING}, sorted(switches.ignored()))") % str(out)
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env)
    got, ignored = p.stdout.rsplit("} ", 1)
    assert all(f"'{n}': None" in got for n in weak), p.stdout                       # none of them followed
    assert all(n in ignored for n in weak), p.stdout
    p = subprocess.run([sys.executable, "-I", str(out / "guard_cli.py"), "verify"], capture_output=True, text=True, env=env)
    assert "Env var AASM_RULES_DIR ignored" in p.stdout, p.stdout
    # the clearest case: a tiny deadline would let the hook time out and the command through
    ev = json.dumps({"tool_name": "Bash", "cwd": t, "tool_input": {"command": "echo x >> .claude/settings.json"}})
    p = subprocess.run([sys.executable, "-I", str(out / "hooks" / "pretooluse_check.py")], input=ev, capture_output=True,
                       text=True, env=env)
    assert p.stdout.strip() and json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", p.stdout + p.stderr
    # the settings file is how the user switches a check off; the environment stays ignored
    (home / ".aasm").mkdir(parents=True)
    (home / ".aasm" / "config.json").write_text(json.dumps({"env": {"AASM_MCP_SCAN": "0"}}))
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env)
    assert "'AASM_MCP_SCAN': '0'" in p.stdout and "'AASM_RULES_DIR': None" in p.stdout, p.stdout
    # ... and an agent writing that file is stopped like one editing the guard (".aasm/" is a protected path)
    for tool, inp in (("Bash", {"command": "echo '{}' > ~/.aasm/config.json"}),
                      ("Write", {"file_path": str(home / ".aasm" / "config.json"), "content": "{}"})):
        hook = "pretooluse_check.py" if tool == "Bash" else "pretooluse_editwrite_check.py"
        ev = json.dumps({"tool_name": tool, "cwd": t, "tool_input": inp})
        p = subprocess.run([sys.executable, "-I", str(out / "hooks" / hook)], input=ev, capture_output=True, text=True, env=env)
        assert p.stdout.strip() and json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", (tool, p.stdout + p.stderr)
print("switches: all cases passed")
