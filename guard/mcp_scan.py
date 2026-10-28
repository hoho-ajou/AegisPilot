"""
AegisPilot - what an MCP server registration brings in, scanned before it is registered.

Registering a local MCP server means its launch command will run with the agent: `npx -y pkg` and `uvx pkg` fetch a
package and run it, `node ./server.js` runs a script on disk. So the launch command is read like an install command
(install_parse: PyPI and npm packages, the script-install check) and a script it runs is read as a bundle; the
install decision (guard_core.check_parsed) then decides as it does for `pip install` / `npm install`.

Not scanned: remote servers (url / http / sse: the code runs elsewhere), container images (docker / podman), a
`python -m module` that is already installed (which package it belongs to is not known here).
Called from the MCP config write check and from `claude mcp add` (guard_core); plugins hand their .mcp.json here too.
"""
from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

_SCRIPT_RUNNERS = {"node", "nodejs", "deno", "bun", "python", "python3", "sh", "bash", "ts-node", "tsx"}
_CONTAINER = {"docker", "podman", "nerdctl"}


def launch_command(entry: dict) -> str | None:
    """The command line of a local server entry ({"command", "args"}), None for a remote one (url / http / sse)."""
    if not isinstance(entry, dict):
        return None
    if entry.get("url") or entry.get("httpUrl") or entry.get("serverUrl") or \
            str(entry.get("type", "")).lower() in ("http", "sse", "streamable-http"):
        helper = entry.get("http_headers_helper")             # Codex: a local command that prints the headers
        return helper if isinstance(helper, str) and helper.strip() else None
    cmd = entry.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        return None
    args = [str(a) for a in entry.get("args", []) if isinstance(a, (str, int, float))]
    return shlex.join([cmd] + args) if args else cmd


def _script(toks: list[str], cwd: Path | None) -> Path | None:
    """The script file a runner command executes (`node ./build/index.js`, `python server.py`), if it exists."""
    if not toks or Path(toks[0]).name not in _SCRIPT_RUNNERS:
        return None
    for t in toks[1:]:
        if t.startswith("-"):
            if t in ("-m", "-c", "-e", "--eval"):
                return None
            continue
        p = Path(os.path.expandvars(t)).expanduser()
        if not p.is_absolute() and cwd is not None:
            p = cwd / p
        return p if p.is_file() else None
    return None


def scannable(launch: str | None) -> bool:
    """Is there local code to scan behind this launch command (not remote, not a container)?"""
    if not launch:
        return False
    try:
        toks = shlex.split(launch)
    except ValueError:
        return True
    return bool(toks) and Path(toks[0]).name not in _CONTAINER


def parsed_for(servers: list[dict], cwd: str | Path | None, env: dict | None = None):
    """install_parse.Parsed for the launch commands of `servers` ([{name, launch}]), or None when nothing is scannable."""
    from install_parse import Parsed, parse_install_command
    base = Path(cwd) if cwd else None
    parsed = Parsed()
    for s in servers:
        cmd = s.get("launch")
        if not cmd:
            continue
        try:
            toks = shlex.split(cmd)
        except ValueError:
            parsed.add_unscanned("unparsed", cmd[:120], "could not parse the MCP server launch command")
            continue
        if not scannable(cmd):
            continue                                   # a container: like a remote server, the registration check asks
        parse_install_command(cmd, base, env if env is not None else dict(os.environ), parsed)
        script = _script(toks, base)
        if script is not None:
            short = re.sub(r"[^A-Za-z0-9._-]+", "-", str(s.get("name", ""))).strip("-")[:60] or "mcp-server"
            parsed.bundles.append({"name": short, "label": f"MCP {s.get('name', '')}".strip(), "kind": "mcp_server",
                                   "paths": [str(script)]})
    if not (parsed.packages or parsed.unscanned or parsed.local_files or parsed.ecosystem_packages or parsed.bundles):
        return None
    return parsed


def decide(servers: list[dict], project_dir: str, agent=None):
    """guard_core.Decision for what the servers' launch commands bring in, or None when there is nothing to scan."""
    parsed = parsed_for(servers, project_dir)
    if parsed is None:
        return None
    import guard_core
    names = ", ".join(str(s.get("name", "")) for s in servers[:3])
    return guard_core.check_parsed(parsed, f"MCP server registration ({names}): " + " ; ".join(s["launch"] for s in servers if s.get("launch"))[:240],
                                   project_dir, agent)
