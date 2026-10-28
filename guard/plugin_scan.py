"""
AegisPilot - a Claude Code plugin, scanned before it is installed.

A plugin is a folder of skills, commands, agents, hooks and MCP servers that run with the agent. `claude plugin install
name@market` looks the plugin up in the marketplace's catalogue (.claude-plugin/marketplace.json, in the marketplace's
local copy that `claude plugin marketplace add` made) and installs what its entry points at:

  "./plugins/x"                                   a folder inside the marketplace copy (already on disk)
  {"source": "github", "repo": "o/r", "ref"|"sha"}   a GitHub repository
  {"source": "url", "url": "https://….git", "ref"|"sha"}             a git repository
  {"source": "git-subdir", "url": …, "path": "plugins/x", "ref"|"sha"}   a folder inside one

The folder is fetched without running anything (sources/repo.py) and read as a bundle (every language is code); the
plugin's own MCP servers go through mcp_scan like any other registration. The install decision is guard_core's.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path


def _load(path: Path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def find(spec: str, agent: str, env: dict | None = None) -> tuple[dict, Path] | tuple[None, str]:
    """(the plugin's catalogue entry, the marketplace copy) for "name@market" of `agent` (or a bare name: the first
    marketplace that lists it), else (None, why). Marketplace layout: agent_formats.json "marketplaces"."""
    import agent_config
    name, _, market = spec.partition("@")
    found = agent_config.marketplaces(agent, env)
    cat_path = agent_config.catalogue(agent)
    if not cat_path:
        return None, f"marketplace format of {agent} unknown"
    for mname, mdir in ([(market, found[market])] if market in found else []) if market else found.items():
        cat = _load(mdir / cat_path)
        for p in (cat or {}).get("plugins", []) if isinstance(cat, dict) else []:
            if isinstance(p, dict) and p.get("name") == name:
                return p, mdir
    if market and market not in found:
        return None, f"plugin not checked: no local copy of marketplace '{market}'"
    return None, f"plugin '{name}' not found in the marketplace list"


def fetch(entry: dict, market_dir: Path, dest: Path) -> tuple[Path, str]:
    """(the plugin folder on disk, where it came from)."""
    from sources import repo
    src = entry.get("source")
    if isinstance(src, str):
        target = (market_dir / src).resolve()
        if market_dir.resolve() not in target.parents and target != market_dir.resolve():
            raise ValueError("plugin path points outside the marketplace")
        if not target.is_dir():
            raise ValueError(f"no '{src}' folder in the marketplace copy")
        return target, f"{market_dir.name}/{src}"
    if not isinstance(src, dict):
        raise ValueError("could not parse the plugin source format")
    kind = src.get("source")
    ref = src.get("sha") or src.get("ref")
    if kind == "github":
        url = f"https://github.com/{src.get('repo', '')}"
    elif kind in ("url", "git-subdir"):
        url = str(src.get("url", ""))
    else:
        raise ValueError(f"plugin source '{kind}' cannot be checked")
    path = src.get("path") if kind == "git-subdir" else None
    return repo.fetch(url, ref, dest, path), f"{url}{'@' + ref if ref else ''}{' ' + path if path else ''}"


def _manifest(root: Path) -> dict:
    """The plugin's definition file, whichever agent's layout it uses (agent_formats.json "plugin_manifest")."""
    import agent_config
    for rel in agent_config.plugin_manifests():
        doc = _load(root / rel)
        if isinstance(doc, dict):
            return doc
    return {}


def _fill_root(text: str, root: Path) -> str:
    import agent_config
    for var in agent_config.vars_of("plugin_root"):
        text = text.replace("${" + var + "}", str(root)).replace("$" + var, str(root))
    return text


def mcp_servers(root: Path) -> list[dict]:
    """The plugin's MCP servers ([{name, launch}]) from .mcp.json or the manifest's "mcpServers"; the agent's plugin-root
    variable is the plugin folder."""
    import mcp_scan
    out = []
    manifest = _manifest(root)
    srcs = [_load(root / ".mcp.json") or {}]
    ms = manifest.get("mcpServers") if isinstance(manifest, dict) else None
    if isinstance(ms, str):
        srcs.append(_load(root / ms) or {})
    elif isinstance(ms, dict):
        srcs.append({"mcpServers": ms})
    for doc in srcs:
        servers = doc.get("mcpServers", doc) if isinstance(doc, dict) else {}
        for name, e in (servers or {}).items():
            launch = mcp_scan.launch_command(e) if isinstance(e, dict) else None
            if launch:
                launch = _fill_root(launch, root)
            out.append({"name": f"{root.name}:{name}", "launch": launch})
    return out


def hook_commands(root: Path) -> list[dict]:
    """The plugin's hooks: hooks/hooks.json, or plugin.json "hooks" (a path or the hooks themselves)."""
    import hook_scan
    manifest = _manifest(root)
    docs = [_load(root / "hooks" / "hooks.json") or {}]
    h = manifest.get("hooks") if isinstance(manifest, dict) else None
    if isinstance(h, str):
        docs.append(_load(root / h) or {})
    elif isinstance(h, dict):
        docs.append({"hooks": h} if "hooks" not in h else h)
    out = []
    for d in docs:
        out += [c for c in hook_scan.commands_in(d) if c not in out]
    return out


def _add_plugin(parsed, spec: str, root: Path, origin: str, env: dict | None) -> None:
    """The plugin folder as a bundle (with its hook command lines as texts) and its MCP servers' launch commands."""
    import hook_scan
    import mcp_scan
    bundle = {"name": _short(spec.partition("@")[0]), "label": f"plugin {spec}", "kind": "plugin",
              "paths": [str(root)], "origin": origin}
    hooks = hook_commands(root)
    if hooks:                                       # the plugin's hook command lines are code too (scripts are in the folder)
        import agent_config
        roots = {v: str(root) for v in agent_config.vars_of("plugin_root")}
        bundle["texts"] = hook_scan.bundle_for(hooks, spec, roots, root)["texts"]
    parsed.bundles.append(bundle)
    sub = mcp_scan.parsed_for(mcp_servers(root), root, env)
    if sub is not None:
        parsed.merge(sub)


def parsed_for(specs: list[str], project_dir: str, dest: Path, env: dict | None, agent: str):
    """install_parse.Parsed for `<agent> plugin install` of the plugins: fetched from the marketplace's entry."""
    from install_parse import Parsed
    parsed = Parsed()
    for spec in specs:
        entry, where = find(spec, agent, env)
        if entry is None:
            parsed.add_unscanned("requirements_unreadable", spec[:120], where)
            continue
        try:
            root, origin = fetch(entry, where, dest / re.sub(r"\W+", "_", spec))
        except Exception as e:
            parsed.add_unscanned("requirements_unreadable", spec[:120], f"plugin not checked, download failed: {str(e)[:120]}")
            continue
        _add_plugin(parsed, spec, root, origin, env)
    return parsed


def parsed_for_enabled(file_path: str, proposed_text: str | None, dest: Path, env: dict | None = None):
    """install_parse.Parsed for plugins a settings write switches on (agent_formats.json "plugins": Claude Code
    enabledPlugins, Codex [plugins."name@market"]), read from where the agent installed them; None when none is new."""
    import agent_config
    from install_parse import Parsed
    try:
        old_text = Path(file_path).read_text()
    except OSError:
        old_text = ""
    parsed, found = Parsed(), False
    for agent, kind, spec in agent_config.specs_for(file_path):
        if kind != "plugins":
            continue
        new_doc = agent_config.parse(proposed_text, spec["format"])
        if new_doc is None:
            continue
        added = agent_config.enabled_plugins(new_doc, spec) - agent_config.enabled_plugins(agent_config.parse(old_text, spec["format"]) or {}, spec)
        for key in sorted(added):
            found = True
            dirs = agent_config.plugin_dirs(agent, key, env)
            if dirs:
                _add_plugin(parsed, key, dirs[0], f"{agent} {dirs[0]}", env)
                continue
            entry, where = find(key, agent, env)
            if entry is None:
                parsed.add_unscanned("requirements_unreadable", key[:120], f"{agent} plugin enabled, but {where}")
                continue
            try:
                root, origin = fetch(entry, where, dest / re.sub(r"\W+", "_", key))
                _add_plugin(parsed, key, root, origin, env)
            except Exception as e:
                parsed.add_unscanned("requirements_unreadable", key[:120], f"plugin not checked, download failed: {str(e)[:120]}")
    return parsed if found else None


def _short(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")[:60] or "plugin"


def decide(specs: list[str], project_dir: str, agent, agent_name: str):
    """guard_core.Decision for installing the plugins, or None when there is nothing to decide."""
    if not specs:
        return None
    import guard_core
    with tempfile.TemporaryDirectory() as tmp:
        parsed = parsed_for(specs, project_dir, Path(tmp), None, agent_name)
        return guard_core.check_parsed(parsed, "plugin install: " + ", ".join(specs)[:200], project_dir, agent)
