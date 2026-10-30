"""Actions on the guard itself ask a person in both modes, with no ack: turning the plugin off, editing the guard's
files or records (.aegis/, ~/.aegis/), a settings edit that drops the guard's hook / disables the plugin / disables all
hooks, a shell write to agent settings, and the guard CLI commands that replace or remove a guard. Other settings changes
keep the auto-mode evidence card. Offline. run: python3 tests/test_self_protection.py"""
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
os.environ.update({"AEGIS_ML": "0", "AEGIS_MCP_SCAN": "0", "HOME": tempfile.mkdtemp()})
import guard_core  # noqa: E402

guard_core.check_integrity = lambda: []
HOOK = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
    {"type": "command", "command": "python3 -I /opt/aegis/hooks/pretooluse_check.py"}]}]}}

for mode in ("auto", "user"):
    os.environ["AEGIS_MODE"] = mode
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
            "rm ~/.aegis": cmd("rm -rf ~/.aegis/rules"),
            "shell settings": cmd("echo '{}' > .claude/settings.json"),
            "guard repair": cmd("python3 -I /opt/aegis/guard_cli.py repair --from /tmp/x --yes"),
            "guard installs": cmd("script -qc 'python3 /opt/aegis/guard_cli.py installs'"),
            "rm .aegis": cmd("rm -rf .aegis"),                                               # no trailing slash
            "rm abs .aegis": cmd(f"rm -rf {d}/.aegis"),
            "rm guard dir": cmd(f"rm -rf {guard_core.Path(guard_core.__file__).resolve().parent}"),
            "mv guard dir": cmd(f"mv \"{guard_core.Path(guard_core.__file__).resolve().parent}\" /tmp/x"),
            "rm plugins": cmd("rm -rf ~/.claude/plugins"),
            "policy file": write(Path(d, ".aegis", "policy.json"), '{"mode": "auto", "allow": []}'),
            "hook removed": write(settings, json.dumps({"hooks": {}})),
            "plugin off": write(settings, json.dumps({**HOOK, "enabledPlugins": {"aegis-pilot@hoho-ajou": False}})),
            "all hooks off": write(settings, json.dumps({**HOOK, "disableAllHooks": True})),
            "broken json": write(settings, json.dumps(HOOK)[:-3]),
            "unknown result": write(settings, None),
        }
        for name, dec in always.items():
            assert dec.action == "confirm", (mode, name, dec)
            assert "ack id" not in dec.reason, (mode, name, dec)          # nothing the agent can grant itself
        rec = json.loads(Path(d, ".aegis", "last_review.json").read_text())
        assert rec.get("always_ask") is True, rec

        # not the guard: another setting keeps the mode's usual handling (auto: the agent's evidence card)
        other = write(settings, json.dumps({**HOOK, "permissions": {"allow": ["Bash(npm test)"]}}))
        assert other.action == ("refuse" if mode == "auto" else "confirm"), (mode, other)
        if mode == "auto":
            assert "ack id" in other.reason, other
        assert cmd("python3 -I /opt/aegis/guard_cli.py ack 0123abcd").action == "allow"       # the ack itself still runs
        assert cmd("cat .claude/settings.json").action == "allow"                             # reading is not changing
        assert cmd("rm -rf .aegisx").action == "allow"                                          # another name

# other ways to write the guard's files from a shell are changes too (each one went unflagged in an audit, 2026-10-30);
# reading stays allowed
import guard_paths  # noqa: E402
for c in ["python3 -c \"open('.aegis/policy.json','w').write('{}')\"", "ln -sf /tmp/x .aegis/policy.json",
          "install -D x .aegis/policy.json", "rsync x .aegis/policy.json", "perl -pi -e s/user/auto/ .aegis/policy.json",
          "touch .aegis/policy.json", "git checkout -- .claude/settings.json", "rm -rf .ae*", "cp x .ae?is/policy.json",
          "node -e \"require('fs').writeFileSync('.aegis/x','')\""]:
    assert guard_paths.command_touches_protected_path(c), c
for c in ["python3 -c \"import json;print(json.load(open('.aegis/last_review.json')))\"", "rm *.log", "ls .aegis",
          "grep auto .aegis/policy.json", "rm -rf build/*"]:
    assert not guard_paths.command_touches_protected_path(c), c
print("self_protection: all cases passed")
