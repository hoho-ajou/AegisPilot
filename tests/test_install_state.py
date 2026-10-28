"""More than one install of the guard (plugin, hooks in a settings file, system install): found, warned about at
session start, and turned off only when a person chooses in a terminal. Uses a fake home. run:
python3 tests/test_install_state.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "guard"
home = Path(tempfile.mkdtemp())
cfg, proj = home / ".claude", home / "proj"
env = {**os.environ, "HOME": str(home), "CLAUDE_CONFIG_DIR": str(cfg), "CLAUDE_PROJECT_DIR": str(proj)}
env.pop("SUDO_USER", None)
os.environ.update(env)
sys.path.insert(0, str(GUARD))
import install_state as st  # noqa: E402

(cfg / "plugins").mkdir(parents=True)
(proj / ".claude").mkdir(parents=True)
(cfg / "plugins" / "installed_plugins.json").write_text(json.dumps(
    {"version": 2, "plugins": {"aegis-pilot@hoho-ajou": [{"scope": "user"}], "other@x": [{"scope": "user"}]}}))
(cfg / "settings.json").write_text(json.dumps({"enabledPlugins": {"aegis-pilot@hoho-ajou": True}, "model": "x"}))
manual = {"hooks": {"PreToolUse": [
    {"matcher": "Bash", "hooks": [{"type": "command", "command": "python3 -I /opt/g/hooks/pretooluse_check.py"},
                                  {"type": "command", "command": "./lint.sh"}]},
    {"matcher": "Edit|MultiEdit|Write", "hooks": [{"type": "command", "command": "python3 -I /opt/g/hooks/pretooluse_editwrite_check.py"}]}]},
    "permissions": {"allow": ["Bash(ls)"]}}
(proj / ".claude" / "settings.json").write_text(json.dumps(manual))

found = st.find(proj)
assert [i["kind"] for i in found] == ["plugin", "settings"], found
assert found[0]["where"] == "aegis-pilot@hoho-ajou"

# session start of the plugin: warns about the manual hooks, names the command to fix it
out = subprocess.run([sys.executable, "-I", str(GUARD / "install_state.py"), "--session"], env=env, capture_output=True,
                     text=True).stdout
assert "runs twice" in out and str(proj / ".claude" / "settings.json") in out and "guard_cli.py\" installs" in out, out

# an agent's shell (no terminal): warned, nothing changed - also for snippet, whose stdout stays empty
before = (proj / ".claude" / "settings.json").read_text()
r = subprocess.run([sys.executable, "-I", str(GUARD / "guard_cli.py"), "installs"], env=env, capture_output=True,
                   text=True, cwd=proj, stdin=subprocess.DEVNULL)
assert r.returncode == 1 and "Nothing changed" in r.stdout, r.stdout
s = subprocess.run([sys.executable, "-I", str(GUARD / "guard_cli.py"), "snippet"], env=env, capture_output=True,
                   text=True, cwd=proj, stdin=subprocess.DEVNULL)
assert s.stdout == "" and "already installed" in s.stderr and "Nothing changed" in s.stderr, (s.stdout, s.stderr)
assert (proj / ".claude" / "settings.json").read_text() == before

# a re-run of snippet for the copy that is already in the settings is not a second install
same = home / "same"; (same / ".claude").mkdir(parents=True)
(same / ".claude" / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
    {"type": "command", "command": f"python3 -I {GUARD}/hooks/pretooluse_check.py"}]}]}}))
(cfg / "settings.json").write_text(json.dumps({"enabledPlugins": {"aegis-pilot@hoho-ajou": False}, "model": "x"}))
s2 = subprocess.run([sys.executable, "-I", str(GUARD / "guard_cli.py"), "snippet"], env=env, capture_output=True,
                    text=True, cwd=same, stdin=subprocess.DEVNULL)
assert '"PreToolUse"' in s2.stdout and "already installed" not in s2.stderr, (s2.stdout, s2.stderr)
(cfg / "settings.json").write_text(json.dumps({"enabledPlugins": {"aegis-pilot@hoho-ajou": True}, "model": "x"}))

# the person chose: the manual hooks go (other hooks and settings stay, backup kept), the plugin is switched off
msg = st.turn_off(found[1])
doc = json.loads((proj / ".claude" / "settings.json").read_text())
assert doc["hooks"] == {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "./lint.sh"}]}]}, doc
assert doc["permissions"] == manual["permissions"] and (proj / ".claude" / "settings.json.bak").read_text() == before, msg
st.turn_off(found[0])
assert json.loads((cfg / "settings.json").read_text()) == {"enabledPlugins": {"aegis-pilot@hoho-ajou": False}, "model": "x"}
assert st.find(proj) == []
out = subprocess.run([sys.executable, "-I", str(GUARD / "install_state.py"), "--session"], env=env, capture_output=True,
                     text=True).stdout
assert out == "", out
print("install_state: all cases passed")
