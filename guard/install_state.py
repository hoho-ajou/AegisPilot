"""
AegisPilot - where this guard is installed: the Claude Code plugin, hooks in a settings file (a manual install or
Codex), or a system install. Two of them at once run every check twice, so a new install warns and lets the person
skip it or turn the others off, and the plugin says so at session start.

Nothing here changes a file unless a person answers in a terminal (stdin and stderr are TTYs). An agent's shell gets
the warning and nothing else; running these commands through the agent also asks the person first (guard_paths).
A changed settings file is backed up next to itself as <name>.bak first.

  python3 install_state.py --session     the session-start warning (prints nothing when there is one install)
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

PLUGIN_NAMES = {"aegis-pilot", "agent-dependency-guard"}
HOOK_MARKERS = ("pretooluse_check.py", "pretooluse_editwrite_check.py", "codex_pretooluse.py")
MANAGED_DIRS = (Path("/etc/claude-code"), Path("/Library/Application Support/ClaudeCode"))


def user_home() -> Path:
    """The person's home, also under sudo (a system install runs as root)."""
    user = os.environ.get("SUDO_USER")
    if user and os.geteuid() == 0:
        try:
            import pwd
            return Path(pwd.getpwnam(user).pw_dir)
        except (KeyError, ImportError):
            pass
    return Path.home()


def config_dir() -> Path:
    if os.environ.get("CLAUDE_CONFIG_DIR") and not os.environ.get("SUDO_USER"):
        return Path(os.environ["CLAUDE_CONFIG_DIR"])
    return user_home() / ".claude"


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _guard_commands(doc) -> list[str]:
    """Hook commands in a settings document that run this guard."""
    out = []
    def walk(v):
        if isinstance(v, dict):
            c = v.get("command")
            if isinstance(c, str) and any(m in c for m in HOOK_MARKERS):
                out.append(c)
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk((doc or {}).get("hooks") if isinstance(doc, dict) else None)
    return out


def settings_files(project_dir: Path | None) -> list[Path]:
    cfg, home = config_dir(), user_home()
    files = [cfg / "settings.json", cfg / "settings.local.json", home / ".codex" / "hooks.json"]
    if project_dir:
        p = Path(project_dir)
        files += [p / ".claude" / "settings.json", p / ".claude" / "settings.local.json", p / ".codex" / "hooks.json"]
    seen, out = set(), []
    for f in files:
        key = str(f.resolve()) if f.exists() else str(f)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def find(project_dir: Path | None = None) -> list[dict]:
    """[{kind: plugin|settings|system, where, ...}] for every install of this guard that would run."""
    out = []
    cfg = config_dir()
    installed = ((_load(cfg / "plugins" / "installed_plugins.json") or {}).get("plugins") or {})
    enabled = ((_load(cfg / "settings.json") or {}).get("enabledPlugins") or {})
    for key in installed:
        if key.split("@", 1)[0] in PLUGIN_NAMES and enabled.get(key, True) is not False:
            out.append({"kind": "plugin", "where": key, "file": str(cfg / "settings.json")})
    for f in settings_files(project_dir):
        cmds = _guard_commands(_load(f))
        if cmds:
            out.append({"kind": "settings", "where": str(f), "commands": cmds})
    for d in MANAGED_DIRS:
        for f in [d / "managed-settings.json"] + sorted((d / "managed-settings.d").glob("*.json")):
            if _guard_commands(_load(f)):
                out.append({"kind": "system", "where": str(f)})
    return out


def describe(item: dict) -> str:
    return {"plugin": f"Claude Code plugin {item['where']}",
            "settings": f"hooks in {item['where']}",
            "system": f"system install ({item['where']})"}[item["kind"]]


def _write_with_backup(path: Path, doc: dict) -> None:
    backup = path.with_name(path.name + ".bak")
    shutil.copy2(path, backup)
    st = path.stat()
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if os.geteuid() == 0:                                   # under sudo: the person keeps owning their files
        for p in (path, backup):
            try:
                os.chown(p, st.st_uid, st.st_gid)
            except OSError:
                pass


def turn_off(item: dict) -> str:
    """Turn one install off. Returns what was done (or what the person has to do)."""
    if item["kind"] == "plugin":
        path = Path(item["file"])
        doc = _load(path) or {}
        doc.setdefault("enabledPlugins", {})[item["where"]] = False
        if path.exists():
            _write_with_backup(path, doc)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        return f"disabled the plugin {item['where']} in {path}"
    if item["kind"] == "settings":
        path = Path(item["where"])
        doc = _load(path)
        if not isinstance(doc, dict):
            return f"could not read {path}; remove the AegisPilot hooks there yourself"
        hooks = doc.get("hooks") or {}
        for event in list(hooks):
            groups = []
            for g in hooks[event] if isinstance(hooks[event], list) else []:
                if isinstance(g, dict) and isinstance(g.get("hooks"), list):
                    g = {**g, "hooks": [h for h in g["hooks"]
                                        if not any(m in str((h or {}).get("command", "")) for m in HOOK_MARKERS)]}
                    if not g["hooks"]:
                        continue
                groups.append(g)
            if groups:
                hooks[event] = groups
            else:
                del hooks[event]
        doc["hooks"] = hooks
        if not hooks:
            del doc["hooks"]
        _write_with_backup(path, doc)
        return f"removed the AegisPilot hooks from {path} (backup: {path.name}.bak)"
    return f"system install: run `sudo python3 <its folder>/guard_cli.py system-uninstall` ({item['where']})"


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stderr.isatty()


def ask_skip_or_overwrite(existing: list[dict], new: str) -> str:
    """'skip' or 'overwrite' (the existing installs were turned off). Messages go to stderr: stdout may be a snippet."""
    err = sys.stderr
    print(f"AegisPilot is already installed here, so {new} would run every check twice:", file=err)
    for item in existing:
        print(f"  - {describe(item)}", file=err)
    if not interactive():
        print("Nothing changed. Run this in a terminal to choose: skip, or overwrite (turn the existing install off).",
              file=err)
        return "skip"
    answer = input("[s]kip / [o]verwrite (turn the existing install off) [s]: ").strip().lower()
    if answer not in ("o", "overwrite"):
        print("Skipped.", file=err)
        return "skip"
    for item in existing:
        print("  " + turn_off(item), file=err)
    return "overwrite"


def session_warning(plugin_root: Path, project_dir: Path | None) -> str:
    """At session start of the plugin: the other installs that also run (each check would run twice)."""
    others = [i for i in find(project_dir) if i["kind"] != "plugin"]
    if not others:
        return ""
    where = "; ".join(describe(i) for i in others[:3])
    return (f"[AegisPilot] Also installed outside this plugin ({where}), so each check runs twice. "
            f"To keep one, run in a terminal: python3 \"{plugin_root / 'guard_cli.py'}\" installs")


if __name__ == "__main__":
    if sys.argv[1:] == ["--session"]:
        try:
            msg = session_warning(Path(__file__).resolve().parent, Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()))
        except Exception:
            msg = ""
        if msg:
            print(msg)
        sys.exit(0)
    print(__doc__)
