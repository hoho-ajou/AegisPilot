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

# the same writes spelled so that the protected name never appears as such, or reached another way (two reviews,
# 2026-10-30): the command is read the way the shell splits it, without running anything
WRITES = [
    # an interpreter fed by a here-document, a here-string or a pipe runs a program like python3 -c does
    "python3 - <<'X'\nopen('.aegis/policy.json','w').write('{}')\nX",
    "python3 <<X\nimport json;json.dump({},open('.aegis/policy.json','w'))\nX",
    "node <<X\nrequire('fs').writeFileSync('.claude/settings.json','{}')\nX",
    "echo \"open('.aegis/policy.json','w').write('{}')\" | python3",
    "python3 <<< \"open('.aegis/policy.json','w').write('{}')\"",
    "cat > /tmp/w.py <<'X'\nopen('.aegis/policy.json','w').write('{}')\nX\npython3 /tmp/w.py",
    # quotes, escapes, // and /./ and .. removed the way the shell and the file system do
    "cp a ~/.claude//settings.json", "cp a ~/.claude/./settings.json", "cp a ~/.claude/../.claude/settings.json",
    "cp x '.claude'/settings.json", 'cp x .cl""aude/settings.json', r"cp x .claude/sett\ings.json",
    'cp x ~/".aeg""is"/config.json', "cd ~/.aeg''is && echo x > config.json", "cp x \"$HOME/.claude/settings.json\"",
    # a piece built at run time next to a protected-looking name counts as that name
    'cp x "$(printf .%s aegis)"/policy.json', "cp x $D/settings.json", "cp x .`echo aegis`/policy.json",
    # the writer spelled differently
    "/bin/ln -sf /tmp/x .aegis/policy.json", '"ln" -sf /tmp/x .aegis/policy.json', r"\ln -sf /tmp/x .aegis/policy.json",
    "command ln -sf /tmp/x .aegis/policy.json", "sudo -u root cp x ~/.claude/settings.json",
    # patterns and braces the shell expands to a protected name
    "cp x ~/.claude/settings.*", "cp x ~/.claude/setting[s].json", "cp x ~/.claude/{settings,x}.json", "rm -rf .ae*",
    "cp x .[c]laude/settings.json", "rm -rf .claude/*", "rm -rf ~/.aegis/*",
    # case-insensitive file systems
    "cp x .AEGIS/policy.json", "cp x .Claude/Settings.json",
    # a relative path after cd / pushd
    "cd ~/.claude && cp /tmp/a settings.json", "cd .aegis; echo x > policy.json", "cd ~ && cd .claude && mv /tmp/x settings.json",
    "cd .aegis && rm -rf *", "pushd ~/.claude; tee settings.json < /tmp/x",
    # the folder that holds a protected path, replaced or removed as a whole
    "rm -rf .claude", "mv .claude .claude.bak", "cp -r /tmp/fake .claude", "rm -rf ~/.aegis", "mv ~/.claude/ /tmp/old",
    # more writers: git clean / git -C ... checkout, find -delete, php -r, sponge, editors, sh -c, eval, $(...)
    "git clean -fdx", "git clean -f", "git clean -ffdX .", "git -C . checkout HEAD~3 -- .claude/settings.json",
    "git --no-pager checkout HEAD -- .aegis/policy.json", "git -C ~/.claude checkout -- settings.json",
    "git -c core.x=y restore --source=HEAD~5 .aegis", "find . -name policy.json -delete",
    r"find . -name settings.json -exec rm {} \;", "find ~ -path '*/.aegis/*' -delete",
    "php -r 'file_put_contents(\".aegis/policy.json\",\"{}\");'", "sponge .aegis/policy.json < x",
    "jq . x | sponge .claude/settings.json", "vim -c ':wq' ~/.claude/settings.json", "vim -es -c '%d|x' .aegis/policy.json",
    "ex -sc '%d|x' ~/.claude/settings.json", "ed -s .aegis/policy.json < script", 'sh -c "install x .aegis/policy.json"',
    "bash -c 'cp x ~/.claude/settings.json'", "eval 'rm -rf .aegis'", "echo $(rm -rf .aegis)", "dd if=x of=.aegis/policy.json",
    "bash <<X\nrm -rf .aegis\nX", "xargs -I {} cp {} .aegis/policy.json < list",
    # the guard's ML environment installed into
    "cd ~/.aegis/ml/venv && bin/pip install x", "~/.aegis/ml/venv/bin/python -m pip install x", "pip install --target ~/.aegis/ml/x y",
    # hooks switched off through the agent's CLI, or the agent started with another config folder
    "claude config set disableAllHooks true", "claude config set -g hooks '{}'", "claude config set enabledPlugins x",
    '"claude" plugin disable aegis-pilot', "CLAUDE_CONFIG_DIR=/tmp/x claude -p hi", "export CLAUDE_CONFIG_DIR=/tmp/x; claude",
    "env CLAUDE_CONFIG_DIR=/tmp/x claude", "CODEX_HOME=/tmp/x codex exec hi",
    # managed settings and the XDG config folder (adapters/claude_code.CONFIG_FRAGMENTS)
    "cp x /etc/claude-code/managed-settings.json", "sudo rm -rf /etc/claude-code/managed-settings.d", "sudo rm -rf /etc/claude-code",
    "cp x ~/.config/claude/settings.json", "cd /etc/claude-code && sudo tee managed-settings.json < x",
]
READS = [
    # installs, git, reading, and writes elsewhere stay unflagged
    "pip install requests", "npm install", "pip install -r requirements.txt 2>&1 | tail -5", "git status", "git checkout main",
    "git checkout -b feature", "git clean -n", "git clean -fdn", "git clean -fd build/", "git diff .claude/settings.json",
    "cat .claude/settings.json", "grep auto .aegis/policy.json", "ls -la .aegis", "less ~/.claude/settings.json",
    "python3 -c \"import json;print(json.load(open('.aegis/last_review.json')))\"",
    "python3 - <<'X'\nprint(open('.aegis/policy.json').read())\nX", "cat .claude/settings.json | python3 -m json.tool",
    "rm -rf build/", "rm *.log", "cd .aegis && ls", "cd .aegis && cat policy.json", "cd ~/.claude && rm *.log",
    "find . -name '*.pyc' -delete", "find . -type d -name __pycache__ -exec rm -rf {} +", "rm -rf .claude/worktrees/agent-x",
    "git worktree remove .claude/worktrees/agent-x", "claude config set -g theme dark", "claude config get hooks",
    "cp $SRC/a.txt $OUT/b.txt", "cp x ~/notes.txt", "echo hi > out.txt", "mv build dist", "cd /tmp && rm -rf x",
    "python3 x.py > report.txt", "tar czf out.tgz src", "echo $CLAUDE_CONFIG_DIR", "mkdir -p .aegis",
    "cp .env.example .env", "rm -rf .venv", "rm -rf .cache/*", "cd .claude && ls worktrees", "vim -R .claude/settings.json",
]
for c in WRITES:
    assert guard_paths.command_touches_protected_path(c), c
for c in READS:
    assert not guard_paths.command_touches_protected_path(c), c

# a file edit spelled differently is the same file
for p in ["/p/.claude//settings.json", "/p/.claude/./settings.json", "/p/.AEGIS/policy.json", "/p/x/../.aegis/policy.json",
          "/etc/claude-code/managed-settings.json", "/etc/claude-code/managed-settings.d/x.json", "/h/.config/claude/settings.json"]:
    assert guard_paths.file_path_is_protected(p), p
for p in ["/p/.claude/worktrees/a/README.md", "/p/src/settings.py", "/etc/claude-code/managed-mcp.json"]:
    assert not guard_paths.file_path_is_protected(p), p
assert guard_paths.path_is_guard_own("/p/.AEGIS//policy.json")
print("self_protection: all cases passed")
