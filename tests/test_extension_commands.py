"""Extensions through the shell: `claude mcp add` / `claude plugin install` (run: python3 tests/test_extension_commands.py).
Before 2026-10-15 only MCP servers written into config files were checked; the CLI route went around it."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"


def hook(cmd: str, cwd: str):
    ev = {"tool_name": "Bash", "cwd": cwd, "tool_input": {"command": cmd}}
    r = subprocess.run([sys.executable, str(IMPL / "hooks/pretooluse_check.py")], input=json.dumps(ev), capture_output=True,
                       text=True, timeout=60, env={**os.environ, "AASM_MODE": "user", "AASM_MCP_SCAN": "0"})   # scanning: test_mcp_scan.py
    return json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None


with tempfile.TemporaryDirectory() as d:
    asked = {
        "claude mcp add evil-srv -- npx -y evil-mcp": "evil-srv",
        "claude mcp add --transport http sentry https://mcp.sentry.dev/mcp": "sentry",
        "claude mcp add-json x '{\"command\":\"uvx\",\"args\":[\"bad-mcp\"]}'": "uvx bad-mcp",
        "cd x && claude mcp add -s user -e TOKEN=abc s1 -- node srv.js": "s1",
        "claude plugin install helper@some-market": "helper@some-market",
        "claude plugin marketplace add evil/repo": "evil/repo",
        "claude mcp add-from-claude-desktop": "Claude Desktop",
    }
    for cmd, needle in asked.items():
        out = hook(cmd, d)
        assert out and out["permissionDecision"] == "ask" and needle in out["permissionDecisionReason"], (cmd, out)
    rec = json.loads((Path(d) / ".aasm/last_review.json").read_text())
    assert rec["verdict"] == "NEEDS_HUMAN_REVIEW" and rec["servers"]
    for cmd in ("claude mcp add fs -- npx -y @modelcontextprotocol/server-filesystem /",
                "claude plugin install fmt@claude-plugins-official", "claude mcp list", "echo claude mcp add x y"):
        assert hook(cmd, d) is None, cmd
    sys.path.insert(0, str(IMPL))
    from guard_core import command_is_relevant
    assert command_is_relevant("claude mcp add x -- npx y") and not command_is_relevant("claude mcp list")

print("extension_commands: all cases passed")
