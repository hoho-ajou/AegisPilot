"""
AegisPilot - Claude Code adapter (the only place that knows Claude Code's hook contract).

PreToolUse hook contract (verified against https://code.claude.com/docs/en/hooks.md):
  - stdin: JSON with {"tool_name": "Bash", "tool_input": {"command": "..."}, "cwd": "..."}
           or {"tool_name": "Edit"|"MultiEdit"|"Write", "tool_input": {"file_path": ..., ...}}
  - stdout: {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"|"ask",
            "permissionDecisionReason": "..."}}; no output = the normal permission flow
  - exit 1 and a timeout do NOT block (hook_runtime turns its own failures into an answer before that)

Surface detection: a hook gets no field that names the surface, so it is read from the environment Claude Code gives
its hooks. Measured with a probe hook in a clean environment:
    interactive terminal (`claude`)                     CLAUDE_CODE_ENTRYPOINT=cli        SESSION_ATTENDED=1  COLUMNS=67
    headless `claude -p`                                CLAUDE_CODE_ENTRYPOINT=sdk-cli    SESSION_ATTENDED=0
    SDK-style `claude -p --input-format stream-json`    CLAUDE_CODE_ENTRYPOINT=sdk-cli    SESSION_ATTENDED=0
    desktop app session (seen in the app's own tool environment, not yet from inside a hook)
                                                        CLAUDE_CODE_ENTRYPOINT=claude-desktop, CLAUDE_CODE_DESKTOP_APP_VERSION set
Not measured: IDE extensions, GitHub Actions, web/remote sessions, the Python/TS Agent SDK libraries (those report
"unknown" with the raw entrypoint kept, never a guess). TERM_PROGRAM=claude-desktop only says the terminal emulator is
the app's terminal panel; a `claude` started there is still a terminal session (ENTRYPOINT=cli).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

NAME = "claude-code"
SUPPORTS_CONFIRM = True
CONFIG_FRAGMENTS = [".claude/settings.json", ".claude/settings.local.json", ".claude/hooks/"]
MCP_CONFIG_NAMES = (".mcp.json", ".claude.json")
PLUGIN_FRAGMENTS = (".claude/plugins/",)          # installed plugins, the guard among them (guard_paths.guard_own_fragments)
SHELL_TOOLS = ("Bash",)
FILE_TOOLS = ("Edit", "MultiEdit", "Write")
_DECISION = {"confirm": "ask", "refuse": "deny", "ask": "ask", "deny": "deny"}

MIN_COLUMNS, MAX_COLUMNS, DEFAULT_COLUMNS = 40, 100, 60


def detect_surface(env=None) -> dict:
    env = os.environ if env is None else env
    entry = str(env.get("CLAUDE_CODE_ENTRYPOINT", "")).strip()
    attended_raw = env.get("CLAUDE_CODE_SESSION_ATTENDED")
    attended = None if attended_raw in (None, "") else attended_raw != "0"
    if entry == "cli":
        kind = "terminal"
    elif entry == "claude-desktop" or (not entry and env.get("CLAUDE_CODE_DESKTOP_APP_VERSION")):
        kind = "app"
    elif entry.startswith("sdk"):
        kind = "api"
    else:
        kind = "unknown"
    try:
        cols = int(env.get("COLUMNS", ""))
    except (TypeError, ValueError):
        cols = None
    width = max(MIN_COLUMNS, min(MAX_COLUMNS, cols)) if cols else DEFAULT_COLUMNS
    return {"surface": kind, "entrypoint": entry[:30], "attended": attended, "columns": cols, "width": width,
            "app_version": str(env.get("CLAUDE_CODE_DESKTOP_APP_VERSION", ""))[:20]}


def shell_command(event: dict):
    if event.get("tool_name") not in SHELL_TOOLS:
        return None
    command = (event.get("tool_input") or {}).get("command", "")
    return (command, event.get("cwd") or os.getcwd()) if isinstance(command, str) else None


def _proposed_text(tool: str, tool_input: dict, file_path: str) -> str | None:
    """The file's content as it would be AFTER this tool call, or None if it cannot be derived."""
    if tool == "Write":
        content = tool_input.get("content")
        return content if isinstance(content, str) else None
    try:
        text = Path(file_path).read_text()
    except OSError:
        text = ""
    edits = tool_input.get("edits") if tool == "MultiEdit" else [tool_input]
    for e in edits or []:
        old, new = e.get("old_string"), e.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str):
            return None
        if old not in text:
            continue                  # the edit would fail anyway
        text = text.replace(old, new) if e.get("replace_all") else text.replace(old, new, 1)
    return text


def file_write(event: dict, with_text: bool = True):
    """(file_path, proposed text or None, project_dir). The text is only derived when asked (it reads the file)."""
    tool = event.get("tool_name")
    if tool not in FILE_TOOLS:
        return None
    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path", "")
    if not file_path or not isinstance(file_path, str):
        return None
    text = _proposed_text(tool, tool_input, file_path) if with_text else None
    return file_path, text, event.get("cwd") or os.getcwd()


def answer(action: str, reason: str) -> str | None:
    """stdout for a core action; None = print nothing (the command goes through Claude Code's normal permission flow)."""
    decision = _DECISION.get(action)
    if decision is None:
        return None
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": decision,
        "permissionDecisionReason": reason,
    }}, ensure_ascii=False)


# ---- environment Profile (env_profile.py): where Claude Code keeps settings, MCP servers, skills, hooks ----------------

def _config_dir(home, env) -> Path:
    d = env.get("CLAUDE_CONFIG_DIR")
    return Path(d).expanduser() if d else Path(home) / ".claude"


def _load_json(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def credential_files(project, home, env):
    """The agent's own login is an asset too (whoever reads it acts as the user's Claude account)."""
    return [(_config_dir(home, env) / ".credentials.json", "agent_credentials", "Claude Code account token")]


def config_files(project, home, env) -> list:
    """Every Claude Code file read_agent_config reads (for env_profile's change fingerprint)."""
    cdir, project, home = _config_dir(home, env), Path(project), Path(home)
    paths = []
    for base in (cdir, project / ".claude"):
        paths += [base / "settings.json", base / "settings.local.json"]
        paths += sorted(base.glob("skills/*/SKILL.md")) + sorted(base.glob("plugins/*.json"))
    paths += [Path("/etc/claude-code/managed-settings.json"), Path("/etc/claude-code/managed-mcp.json"), project / ".mcp.json",
              home / ".claude.json", home / ".config/Claude/claude_desktop_config.json"] + sorted(home.glob(".claude*/.claude.json"))
    return paths


def read_agent_config(project, home, env) -> dict:
    from env_profile import mcp_server_entry
    cdir = _config_dir(home, env)
    layers = [("managed", Path("/etc/claude-code/managed-settings.json")), ("user", cdir / "settings.json"),
              ("project", Path(project) / ".claude" / "settings.json"),
              ("local", Path(project) / ".claude" / "settings.local.json")]
    perms = {"allow": [], "deny": [], "ask": [], "default_mode": None, "additional_directories": []}
    hooks, sources, sandbox, notes = [], [], None, []
    for scope, path in layers:
        doc = _load_json(path) if path.is_file() else None
        if not isinstance(doc, dict):
            if path.is_file():
                notes.append(f"could not read {scope} settings: {path.name}")
            continue
        sources.append({"scope": scope, "file": str(path)})
        p = doc.get("permissions") if isinstance(doc.get("permissions"), dict) else {}
        for k in ("allow", "deny", "ask"):
            perms[k] += [str(r) for r in p.get(k, []) if isinstance(r, str)]
        if p.get("defaultMode"):
            perms["default_mode"] = str(p["defaultMode"])
        perms["additional_directories"] += [str(d) for d in p.get("additionalDirectories", []) if isinstance(d, str)]
        if isinstance(doc.get("sandbox"), dict):
            sandbox = {"enabled": bool(doc["sandbox"].get("enabled")), "scope": scope}
        for event, groups in (doc.get("hooks") or {}).items() if isinstance(doc.get("hooks"), dict) else []:
            for g in groups if isinstance(groups, list) else []:
                for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                    cmd = str(h.get("command", "")) if isinstance(h, dict) else ""
                    hooks.append({"scope": scope, "event": event, "matcher": g.get("matcher"),
                                  "script": os.path.basename(cmd.split()[-1]) if cmd.split() else None,
                                  "is_guard": "pretooluse_check.py" in cmd or "aegis-pilot" in cmd})
    servers = _claude_mcp_servers(project, home, cdir, mcp_server_entry)
    plugin_servers, plugin_hooks, plugin_skills, enabled = _enabled_plugins(cdir, layers, mcp_server_entry)
    servers += plugin_servers
    hooks += plugin_hooks
    skills = []
    for scope, base in (("user", cdir / "skills"), ("project", Path(project) / ".claude" / "skills")):
        for md in sorted(base.glob("*/SKILL.md")):
            files = [f for f in md.parent.rglob("*") if f.is_file()]
            skills.append({"id": f"skill:{md.parent.name}", "name": md.parent.name, "scope": scope,
                           "has_scripts": any(f.suffix in (".py", ".sh", ".js", ".ts") or os.access(f, os.X_OK) for f in files)})
    skills += plugin_skills
    if enabled and not (plugin_servers or plugin_hooks or plugin_skills):
        notes.append(f"install folder not found for {len(enabled)} enabled plugin(s): their hooks, skills and MCP servers were not collected")
    return {"plugins": enabled, "permissions": perms, "sandbox": sandbox, "hooks": hooks, "guard_installed": any(h["is_guard"] for h in hooks),
            "mcp_servers": servers, "skills": skills, "sources": sources, "notes": notes}


def _display_path(path: Path, home) -> str:
    try:
        return "~/" + str(Path(path).relative_to(home))
    except ValueError:
        return str(path)


def _claude_mcp_servers(project, home, cdir, entry) -> list:
    """Every place Claude Code (and the desktop app) keeps MCP servers: project .mcp.json, each config dir's .claude.json
    (user scope + this project's local scope), the managed file, the desktop app config. Same name in two files = two rows."""
    out = []
    mcp = _load_json(Path(project) / ".mcp.json")
    if isinstance(mcp, dict):
        out += [entry(n, e, "project", "./.mcp.json") for n, e in (mcp.get("mcpServers") or {}).items()]
    states = [Path(home) / ".claude.json", cdir / ".claude.json"] + sorted(Path(home).glob(".claude*/.claude.json"))
    seen = set()
    for state in states:
        state = state.resolve() if state.exists() else state
        if state in seen:
            continue
        seen.add(state)
        doc = _load_json(state)
        if not isinstance(doc, dict):
            continue
        src = _display_path(state, home)
        out += [entry(n, e, "user", src) for n, e in (doc.get("mcpServers") or {}).items()]
        proj = (doc.get("projects") or {}).get(str(project))
        if isinstance(proj, dict):
            out += [entry(n, e, "local", src) for n, e in (proj.get("mcpServers") or {}).items()]
    for scope, path in (("managed", Path("/etc/claude-code/managed-mcp.json")),
                        ("desktop", Path(home) / ".config" / "Claude" / "claude_desktop_config.json")):
        doc = _load_json(path)
        if isinstance(doc, dict):
            out += [entry(n, e, scope, _display_path(path, home)) for n, e in (doc.get("mcpServers") or {}).items()]
    return out


def _plugin_dirs(cdir: Path, name: str, market: str) -> list:
    roots = [cdir / "plugins" / "marketplaces" / market / "plugins" / name, cdir / "plugins" / "marketplaces" / market / name]
    roots += sorted((cdir / "plugins" / "cache" / market / name).glob("*")) if (cdir / "plugins" / "cache" / market / name).is_dir() else []
    roots.append(cdir / "plugins" / "cache" / market / name)
    return [r for r in roots if (r / ".claude-plugin" / "plugin.json").is_file() or (r / ".mcp.json").is_file()]


def _enabled_plugins(cdir: Path, layers, entry):
    """Plugins switched on in any settings layer ("enabledPlugins": {"name@marketplace": true}): their MCP servers, hooks
    and skills run with the agent like the user's own."""
    enabled = []
    for _scope, path in layers:
        doc = _load_json(path) if path.is_file() else None
        for key, on in ((doc or {}).get("enabledPlugins") or {}).items() if isinstance(doc, dict) else []:
            if on and key not in enabled:
                enabled.append(key)
    servers, hooks, skills = [], [], []
    for key in enabled:
        name, _, market = key.partition("@")
        dirs = _plugin_dirs(cdir, name, market)
        if not dirs:
            continue
        d = dirs[0]
        scope = f"plugin:{name}"
        manifest = _load_json(d / ".claude-plugin" / "plugin.json") or {}
        mcp = _load_json(d / ".mcp.json") or {}
        for src in (mcp.get("mcpServers") if isinstance(mcp.get("mcpServers"), dict) else mcp if isinstance(mcp, dict) else {},
                    manifest.get("mcpServers") if isinstance(manifest.get("mcpServers"), dict) else {}):
            for n, e in (src or {}).items():
                if isinstance(e, dict):
                    servers.append(entry(n, e, scope, f"plugin {name}"))
        hk = _load_json(d / "hooks" / "hooks.json") or {}
        for event, groups in (hk.get("hooks") or {}).items() if isinstance(hk.get("hooks"), dict) else []:
            for g in groups if isinstance(groups, list) else []:
                for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                    cmd = str(h.get("command", "")) if isinstance(h, dict) else ""
                    hooks.append({"scope": scope, "event": event, "matcher": g.get("matcher"),
                                  "script": os.path.basename(cmd.split()[-1]) if cmd.split() else None, "is_guard": False})
        for md in sorted((d / "skills").glob("*/SKILL.md")):
            files = [f for f in md.parent.rglob("*") if f.is_file()]
            skills.append({"id": f"skill:{name}:{md.parent.name}", "name": md.parent.name, "scope": scope,
                           "has_scripts": any(f.suffix in (".py", ".sh", ".js", ".ts") or os.access(f, os.X_OK) for f in files)})
    return servers, hooks, skills, enabled


# ---- extensions through the shell: `claude mcp add ...`, `claude plugin install ...` ---------------------------------------------
# The Edit/Write hook already checks MCP servers written into config files; registering one with the CLI went around it
# (a known gap, INSTALL_PATTERNS.md). These commands are Claude Code's own, so they are parsed here.
_MCP_VALUE_OPTS = {"-s", "--scope", "-t", "--transport", "--client-id", "--callback-port"}
_MCP_MULTI_OPTS = {"-e", "--env", "-H", "--header"}
OFFICIAL_MARKETPLACES = ("claude-plugins-official", "anthropic")


def extension_commands(command: str) -> list:
    """[{kind: mcp_server|plugin|marketplace, name, source}] for every extension the command would add or turn on."""
    from install_parse import _segments
    try:
        segments = _segments(command)
    except ValueError:
        return []
    out = []
    for seg in segments:
        toks = list(seg)
        while toks and (toks[0] in ("sudo", "command", "time", "nohup", "exec") or "=" in toks[0] and not toks[0].startswith("-")):
            toks.pop(0)
        if not toks or Path(toks[0]).name != "claude":
            continue
        rest = toks[1:]
        if rest[:2] == ["mcp", "add"]:
            args, pos, i = rest[2:], [], 0
            while i < len(args):
                t = args[i]
                if t == "--":
                    pos += args[i + 1:]
                    break
                if t in _MCP_VALUE_OPTS:
                    i += 2
                    continue
                if t in _MCP_MULTI_OPTS:               # -e KEY=v [KEY2=v2 ...] / -H "X: y" ...
                    i += 1
                    while i < len(args) and not args[i].startswith("-") and ("=" in args[i] or ":" in args[i]):
                        i += 1
                    continue
                if t.startswith("-"):
                    i += 1
                    continue
                pos.append(t)
                i += 1
            if pos:
                out.append({"kind": "mcp_server", "name": pos[0], "source": " ".join(pos[1:]), "via": "claude mcp add"})
        elif rest[:2] == ["mcp", "add-json"]:
            pos = [t for t in rest[2:] if not t.startswith("-")]
            source = ""
            if len(pos) >= 2:
                try:
                    from mcp_guard import _server_source
                    entry = json.loads(pos[1])
                    source = _server_source(entry) if isinstance(entry, dict) else ""
                except ValueError:
                    source = pos[1][:200]
            out.append({"kind": "mcp_server", "name": pos[0] if pos else "?", "source": source, "via": "claude mcp add-json"})
        elif rest[:2] == ["mcp", "add-from-claude-desktop"]:
            out.append({"kind": "mcp_server", "name": "(all Claude Desktop settings)", "source": "claude_desktop_config.json", "via": "claude mcp add-from-claude-desktop"})
        elif rest[:1] in (["plugin"], ["plugins"]) and rest[1:2] in (["install"], ["enable"]):
            for t in [t for t in rest[2:] if not t.startswith("-")][:5]:
                out.append({"kind": "plugin", "name": t, "source": t})
        elif rest[:1] in (["plugin"], ["plugins"]) and rest[1:3] == ["marketplace", "add"]:
            for t in [t for t in rest[3:] if not t.startswith("-")][:3]:
                out.append({"kind": "marketplace", "name": t, "source": t})
    return out


def extension_is_known(entry: dict) -> bool:
    """Official MCP packages (mcp_guard's short list), plugins from the official marketplace, Anthropic's marketplace."""
    from mcp_guard import _is_known_source
    if entry["kind"] == "mcp_server":
        return _is_known_source(entry.get("source", ""))
    if entry["kind"] == "plugin":
        return "@" in entry["name"] and entry["name"].rsplit("@", 1)[1] in OFFICIAL_MARKETPLACES
    return entry.get("source", "").startswith(("anthropics/", "https://github.com/anthropics/"))
