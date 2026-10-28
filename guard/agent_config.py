"""
AegisPilot - every known coding agent's extension settings, read the same way (2026-10-23).

What differs between agents is WHERE their MCP servers, hooks and plugins are written and in WHICH format - that is
data (agent_formats.json). This module reads any of it: which agent setting a path is, the MCP servers / hook commands /
enabled plugins in a document, the plugin folders on disk, and the `<agent> mcp add` command lines. The checks
(mcp_scan, hook_scan, plugin_scan) and the decision (guard_core) never name an agent.

Known agents are recognised whichever agent runs the guard: an agent under Claude Code that edits ~/.codex/config.toml
or .cursor/mcp.json plants an extension in that other agent just the same.
"""
from __future__ import annotations

import json
import os
import re
import tomllib
from pathlib import Path

FORMATS_PATH = Path(__file__).resolve().parent / "agent_formats.json"
KINDS = ("mcp", "hooks", "plugins")


def formats() -> dict:
    global _FORMATS
    try:
        return _FORMATS
    except NameError:
        _FORMATS = json.loads(FORMATS_PATH.read_text())["agents"]
        return _FORMATS


def _matches(file_path: str, names: list[str]) -> bool:
    p = file_path.replace("\\", "/")
    return any(p == n or p.endswith("/" + n) for n in names)


def specs_for(file_path: str) -> list[tuple[str, str, dict]]:
    """[(agent, kind, spec)] of every agent setting `file_path` is (one file can be several: Codex's config.toml holds
    both MCP servers and plugins)."""
    out = []
    for agent, f in formats().items():
        for kind in KINDS:
            for spec in f.get(kind, []):
                if _matches(file_path, spec["files"]):
                    out.append((agent, kind, spec))
    return out


def hook_dirs() -> list[str]:
    return [d for f in formats().values() for d in f.get("hook_dirs", [])]


def in_hook_dir(file_path: str) -> bool:
    p = file_path.replace("\\", "/")
    return any("/" + d in p or p.startswith(d) for d in hook_dirs())


def parse(text: str | None, fmt: str):
    """The document, {} for no text (a new file), None when it cannot be read."""
    if text is None:
        return None
    if not text.strip():
        return {}
    try:
        return tomllib.loads(text) if fmt == "toml" else json.loads(text)
    except (ValueError, tomllib.TOMLDecodeError):
        return None


def walk(doc, dotted: str) -> list:
    """Values at a key path ("projects.*.mcpServers": '*' is any key)."""
    nodes = [doc]
    for part in dotted.split("."):
        nxt = []
        for n in nodes:
            if not isinstance(n, dict):
                continue
            nxt += list(n.values()) if part == "*" else ([n[part]] if part in n else [])
        nodes = nxt
    return nodes


def mcp_servers(doc, spec: dict) -> dict[str, dict]:
    """{name: entry} of the MCP servers a document declares (all key paths of the spec)."""
    out: dict[str, dict] = {}
    for path in spec.get("servers", []):
        for node in walk(doc, path):
            if isinstance(node, dict):
                out.update({str(k): v for k, v in node.items() if isinstance(v, dict)})
    return out


def hook_commands(doc, spec: dict) -> list[dict]:
    import hook_scan
    return [c for node in walk(doc, spec["hooks"]) for c in hook_scan.commands_in({"hooks": node})]


def enabled_plugins(doc, spec: dict) -> set[str]:
    """"name@market" keys switched on: {"x@m": true} (Claude Code) or {"x@m": {"enabled": true}} (Codex)."""
    out = set()
    for node in walk(doc, spec["enabled"]):
        for key, val in (node or {}).items() if isinstance(node, dict) else []:
            on = val.get("enabled", True) if isinstance(val, dict) else bool(val)
            if on:
                out.add(str(key))
    return out


def vars_of(which: str, agent: str | None = None) -> list[str]:
    """Variables an agent fills into hook / MCP commands ("plugin_root", "project_dir"); every agent's when agent is None."""
    agents = [formats()[agent]] if agent in formats() else list(formats().values()) if agent is None else []
    return [v for f in agents for v in f.get("vars", {}).get(which, [])]


def plugin_manifests() -> list[str]:
    return [f["plugin_manifest"] for f in formats().values() if f.get("plugin_manifest")]


def marketplaces(agent: str, env: dict | None = None) -> dict[str, Path]:
    """{marketplace name: its local copy} for an agent with a marketplace layout (agent_formats.json "marketplaces")."""
    m = formats().get(agent, {}).get("marketplaces")
    cdir = config_dir(agent, env)
    if not m or cdir is None:
        return {}
    fill = lambda t: Path(t.replace("{config}", str(cdir)))  # noqa: E731
    out: dict[str, Path] = {}
    try:
        known = json.loads(fill(m["known"]).read_text()) if m.get("known") else {}
    except (OSError, ValueError):
        known = {}
    for name, info in known.items() if isinstance(known, dict) else []:
        loc = info.get("installLocation") if isinstance(info, dict) else None
        out[name] = Path(loc) if loc else fill(m["dirs"]) / name
    base = fill(m["dirs"]) if m.get("dirs") else None
    if base is not None and base.is_dir():
        for d in base.iterdir():
            out.setdefault(d.name, d)
    return out


def catalogue(agent: str) -> str | None:
    return (formats().get(agent, {}).get("marketplaces") or {}).get("catalogue")


def config_dir(agent: str, env: dict | None = None) -> Path | None:
    cd = formats().get(agent, {}).get("config_dir")
    if not cd:
        return None
    env = env if env is not None else os.environ
    if env.get(cd["env"]):
        return Path(env[cd["env"]]).expanduser()
    home = env.get("HOME") or str(Path.home())
    return Path(cd["default"].replace("~", home, 1))


def plugin_dirs(agent: str, spec: str, env: dict | None = None) -> list[Path]:
    """Folders on disk where `name@market` of `agent` is installed (newest version folder first)."""
    name, _, market = spec.partition("@")
    cdir = config_dir(agent, env)
    if cdir is None or not re.fullmatch(r"[\w.-]+", name) or (market and not re.fullmatch(r"[\w.-]+", market)):
        return []
    out = []
    for pattern in formats()[agent].get("plugin_dirs", []):
        base = pattern.replace("{config}", str(cdir)).replace("{market}", market or "*").replace("{name}", name)
        if base.endswith("/*"):
            parent = Path(base[:-2])
            if "*" not in str(parent) and parent.is_dir():
                out += sorted((p for p in parent.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime, reverse=True)
        elif "*" not in base and Path(base).is_dir():
            out.append(Path(base))
    return out


def cli_extensions(command: str) -> list[dict]:
    """[{kind: "mcp_server", name, source, via, agent}] for every `<agent> mcp add ...` in a shell command, for every
    agent that has a CLI in agent_formats.json. `source` is the server's launch command ("" for --url / remote)."""
    from install_parse import _segments
    try:
        segments = _segments(command)
    except ValueError:
        return []
    clis = {f["cli"]["bin"]: (agent, f["cli"]) for agent, f in formats().items() if f.get("cli")}
    out = []
    for seg in segments:
        toks = list(seg)
        while toks and (toks[0] in ("sudo", "command", "time", "nohup", "exec") or "=" in toks[0] and not toks[0].startswith("-")):
            toks.pop(0)
        if not toks or Path(toks[0]).name not in clis:
            continue
        agent, cli = clis[Path(toks[0]).name]
        sub = cli["mcp_add"]
        rest = toks[1:]
        if rest[:len(sub)] != sub:
            continue
        args, pos, i, url = rest[len(sub):], [], 0, None
        while i < len(args):
            t = args[i]
            if t == "--":
                pos += args[i + 1:]
                break
            if t in cli.get("value_opts", []):
                if t == "--url" and i + 1 < len(args):
                    url = args[i + 1]
                i += 2
                continue
            if t in cli.get("multi_opts", []):           # -e KEY=v [KEY2=v2 ...] / -H "X: y" ...
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
            launch = " ".join(pos[1:]) if not url else ""
            out.append({"kind": "mcp_server", "name": pos[0], "source": launch or url or "", "via": f"{cli['bin']} mcp add",
                        "agent": agent})
    return out
