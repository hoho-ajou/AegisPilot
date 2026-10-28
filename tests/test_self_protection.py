"""Actions on the guard itself ask a person in both modes, with no ack: turning the plugin off, editing the guard's
files or records (.aasm/, ~/.aasm/), a settings edit that drops the guard's hook / disables the plugin / disables all
hooks, a shell write to agent settings, and the guard CLI commands that replace or remove a guard. Other settings changes
keep the auto-mode evidence card. Offline. run: python3 tests/test_self_protection.py"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
os.environ.update({"AASM_ML": "0", "AASM_MCP_SCAN": "0", "HOME": tempfile.mkdtemp()})
import guard_core  # noqa: E402

guard_core.check_integrity = lambda: []
HOOK = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
    {"type": "command", "command": "python3 -I /opt/aegis/hooks/pretooluse_check.py"}]}]}}

for mode in ("auto", "user"):
    os.environ["AASM_MODE"] = mode
    with tempfile.TemporaryDirectory() as d:
        settings = Path(d, ".claude", "settings.json")
        settings.parent.mkdir()
        settings.write_text(json.dumps(HOOK))
        cmd = lambda c: guard_core.check_command(c, d)                                    # noqa: E731
        write = lambda p, t: guard_core.check_file_write(str(p), t, d)                     # noqa: E731

        always = {
            "plugin disable": cmd("claude plugin disable aegis-pilot@hoho-ajou"),
            "plugin uninstall": cmd("claude plugin uninstall aegis-pilot"),
            "marketplace remove": cmd("claude plugin marketplace remove hoho-ajou"),
            "rm ~/.aasm": cmd("rm -rf ~/.aasm/rules"),
            "shell settings": cmd("echo '{}' > .claude/settings.json"),
            "guard repair": cmd("python3 -I /opt/aegis/guard_cli.py repair --from /tmp/x --yes"),
            "guard installs": cmd("script -qc 'python3 /opt/aegis/guard_cli.py installs'"),
            "rm .aasm": cmd("rm -rf .aasm"),                                               # no trailing slash
            "rm abs .aasm": cmd(f"rm -rf {d}/.aasm"),
            "rm guard dir": cmd(f"rm -rf {guard_core.Path(guard_core.__file__).resolve().parent}"),
            "mv guard dir": cmd(f"mv \"{guard_core.Path(guard_core.__file__).resolve().parent}\" /tmp/x"),
            "rm plugins": cmd("rm -rf ~/.claude/plugins"),
            "policy file": write(Path(d, ".aasm", "policy.json"), '{"mode": "auto", "allow": []}'),
            "hook removed": write(settings, json.dumps({"hooks": {}})),
            "plugin off": write(settings, json.dumps({**HOOK, "enabledPlugins": {"aegis-pilot@hoho-ajou": False}})),
            "all hooks off": write(settings, json.dumps({**HOOK, "disableAllHooks": True})),
            "broken json": write(settings, json.dumps(HOOK)[:-3]),
            "unknown result": write(settings, None),
        }
        for name, dec in always.items():
            assert dec.action == "confirm", (mode, name, dec)
            assert "ack id" not in dec.reason, (mode, name, dec)          # nothing the agent can grant itself
        rec = json.loads(Path(d, ".aasm", "last_review.json").read_text())
        assert rec.get("always_ask") is True, rec

        # not the guard: another setting keeps the mode's usual handling (auto: the agent's evidence card)
        other = write(settings, json.dumps({**HOOK, "permissions": {"allow": ["Bash(npm test)"]}}))
        assert other.action == ("refuse" if mode == "auto" else "confirm"), (mode, other)
        if mode == "auto":
            assert "ack id" in other.reason, other
        assert cmd("python3 -I /opt/aegis/guard_cli.py ack 0123abcd").action == "allow"       # the ack itself still runs
        assert cmd("cat .claude/settings.json").action == "allow"                             # reading is not changing
        assert cmd("rm -rf .aasmx").action == "allow"                                          # another name
print("self_protection: all cases passed")
