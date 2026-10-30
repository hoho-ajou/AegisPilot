"""
AegisPilot - shared protected-path logic (self-tampering guard).

Scope: agent tool calls (shell commands, file edits) that touch the files the guard itself depends
on to run correctly - not just the agent's settings, but the whole hook/scan_engine footprint, since the hook's own
fail-open design means breaking any of these has the same effect as disabling it outright.

Tool-independent: the guard's own paths are listed here; the agent's own config files (where its hooks are registered)
come from the adapter (adapters/<agent>.CONFIG_FRAGMENTS, MCP_CONFIG_NAMES). `agent=None` means the default adapter.
"""
from __future__ import annotations

import re
from pathlib import Path

# fragments matched against a raw path string (shell command text or a file edit's path) - deliberately broad substring
# matches, not exact paths, since both can appear relative, absolute, or ~-expanded.
GUARD_DIR = Path(__file__).resolve().parent
GUARD_FRAGMENTS = [
    "aegis-pilot/",
    ".aegis/",   # last_review.json and reports/ are what the user is told to trust (agent-writable otherwise)
    str(GUARD_DIR) + "/",   # where this copy really is (a plugin lives in the agent's plugin cache)
]


def guard_own_fragments() -> list[str]:
    """The guard's own paths, plus where each agent keeps installed plugins (adapters' PLUGIN_FRAGMENTS): removing that
    folder removes the guard with the other plugins."""
    from adapters import all_adapters
    frags = list(GUARD_FRAGMENTS)
    for a in all_adapters():
        frags += [f for f in getattr(a, "PLUGIN_FRAGMENTS", ()) if f not in frags]
    return frags


def _fragment_in(frag: str, text: str) -> bool:
    """`frag` in a shell command. A folder fragment ("x/") also matches the folder named without the slash
    (`rm -rf .aegis`, `mv <guard dir> /tmp`), but not a longer name that starts the same (`.aegisx`)."""
    if frag in text:
        return True
    if frag.endswith("/"):
        return re.search(re.escape(frag[:-1]) + r"(?=$|[\s'\";&|)<>])", text) is not None
    return False


def _plugin_names() -> tuple[set, set]:
    """(plugin names, marketplace names) this guard is installed under: its own plugin.json, the marketplace folder of
    the plugin cache it sits in (~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/), plus the default names
    (the plugin and marketplace since 2026-10-25, and the folder name of a manual install)."""
    import json
    plugins, markets = {"aegis-pilot"}, {"hoho-ajou"}
    if len(GUARD_DIR.parents) > 3 and GUARD_DIR.parents[2].name == "cache" and GUARD_DIR.parents[3].name == "plugins":
        markets.add(GUARD_DIR.parents[1].name)
    try:
        plugins.add(json.loads((GUARD_DIR / ".claude-plugin" / "plugin.json").read_text()).get("name"))
    except (OSError, ValueError, AttributeError):
        pass
    ok = lambda v: isinstance(v, str) and re.fullmatch(r"[\w.-]{1,128}", v)
    return {v for v in plugins if ok(v)}, {v for v in markets if ok(v)}


def command_disables_guard(command: str) -> bool:
    """`claude plugin disable|uninstall <the guard>` or removing its marketplace (which uninstalls it): through the
    agent's shell this switches the guard off like editing its hook settings does (2026-10-24, plugin distribution)."""
    if not re.search(r"\bclaude\b[^\n;&|]*\bplugins?\b", command):
        return False
    plugins, markets = _plugin_names()
    for seg in re.split(r"[;&|\n]+", command):
        if not re.search(r"\bclaude\b.*\bplugins?\b", seg):
            continue
        words = re.findall(r"[\w.@/-]+", seg)
        names = {w.split("@", 1)[0] for w in words} | {w.split("@", 1)[1] for w in words if "@" in w}
        if re.search(r"\bplugins?\s+(disable|uninstall|remove|rm)\b", seg) and names & plugins:
            return True
        if re.search(r"\bmarketplace\s+(remove|rm)\b", seg) and names & (markets | plugins):
            return True
    return False


_GUARD_CLI_CHANGES = re.compile(r"guard_cli\.py\W+(installs|repair|system-install|system-uninstall|ml-install|ml-uninstall)\b")


def command_changes_guard_install(command: str) -> bool:
    """`guard_cli.py installs|repair|system-install|system-uninstall|ml-install|ml-uninstall` run by the agent: each can
    turn a guard off or replace what it runs, so it is the person's call even though the guard's own CLI does the work."""
    return bool(_GUARD_CLI_CHANGES.search(command))


def path_is_guard_own(path_text: str) -> bool:
    """The guard itself - its files, its records and its settings (.aegis/, ~/.aegis/) - as opposed to the agent's own
    settings, which are protected too but may be changed for other reasons."""
    return any(frag in path_text for frag in guard_own_fragments())


_GUARD_HOOK_MARKERS = ("pretooluse_check.py", "pretooluse_editwrite_check.py", "codex_pretooluse.py")


def settings_change_disables_guard(file_path: str, proposed_text: str | None) -> bool:
    """An edit of an agent settings file that turns the guard off: one of its hook commands disappears, the guard
    plugin is switched off (enabledPlugins), every hook is disabled (disableAllHooks), or a JSON settings file stops
    parsing (the agent would drop the whole file, hooks included). An edit whose result is unknown counts as one."""
    import json
    if proposed_text is None:
        return True
    try:
        before = Path(file_path).expanduser().read_text(encoding="utf-8", errors="replace")
    except OSError:
        before = ""
    count = lambda t: sum(t.count(m) for m in _GUARD_HOOK_MARKERS)  # noqa: E731
    if count(proposed_text) < count(before):
        return True
    def load(t):
        try:
            v = json.loads(t)
            return v if isinstance(v, dict) else None
        except ValueError:
            return None
    after, was = load(proposed_text), load(before) or {}
    if after is None:
        return file_path.endswith(".json") and bool(before.strip()) and load(before) is not None
    if after.get("disableAllHooks") is True and was.get("disableAllHooks") is not True:
        return True
    plugins, _ = _plugin_names()
    switched_off = {k for k, v in (after.get("enabledPlugins") or {}).items() if v is False}
    already_off = {k for k, v in (was.get("enabledPlugins") or {}).items() if v is False}
    return any(k.split("@", 1)[0] in plugins for k in switched_off - already_off)


def _agent(agent):
    if agent is None:
        from adapters import DEFAULT
        return DEFAULT
    return agent


def protected_fragments(agent=None) -> list[str]:
    """The guard's own paths + the agent's settings/hooks paths.
    MCP config files are deliberately NOT in this list: they have their own, more specific MCP check
    (mcp_guard.check_new_mcp_servers) that distinguishes known from unknown servers, which a generic "protected path"
    flag would shadow - found via testing this exact collision (.mcp.json matched here first and the MCP-specific
    message never fired)."""
    from adapters import all_adapters
    frags = list(_agent(agent).CONFIG_FRAGMENTS)
    for a in all_adapters():                       # every agent's settings, not only the running one's (2026-10-23)
        frags += [f for f in a.CONFIG_FRAGMENTS if f not in frags]
    return frags + [f for f in guard_own_fragments() if f not in frags]


def shell_protected_fragments(agent=None) -> list[str]:
    """Shell-only: MCP config tampering via shell (sed/etc, not a file edit) has no diffing available, so it still falls
    under the generic self-protection catch-all there."""
    return protected_fragments(agent) + list(_agent(agent).MCP_CONFIG_NAMES)


# command tokens that indicate the Bash command WRITES to whatever path it
# names, as opposed to just reading it (cat/grep/ls on a protected path is
# not a tampering attempt). Deliberately conservative: a write-looking token
# anywhere in the command is enough to flag, since under-flagging here is the
# expensive mistake (the whole point is "catch it before the safety net is
# gone").
_WRITE_INDICATOR = re.compile(
    r"\bsed\s+-i\b|\bmv\b|\brm\b|\bcp\b|\btruncate\b|\btee\b|\bchmod\b|>>?|\bdd\b"
)


# `2>&1`, `>&2` and `> /dev/null` only route output streams; they write no file, yet the `>` in them used to make every
# command that merely READ a protected file (`cat .claude/settings.json; pip install ... 2>&1 | tail`) look like tampering
# (found in a real agent run). Only a redirect to an actual path still counts: `> .claude/settings.json`, `>& file`, `&> file`.
_HARMLESS_REDIRECT = re.compile(r"\d*>&\d+|\d*>>?\s*/dev/null|&>>?\s*/dev/null")


def command_touches_protected_path(command: str, agent=None) -> bool:
    """True if a shell command both names a protected path and looks like it writes, or switches the guard plugin off."""
    if command_disables_guard(command):
        return True
    if not any(_fragment_in(frag, command) for frag in shell_protected_fragments(agent)):
        return False
    return bool(_WRITE_INDICATOR.search(_HARMLESS_REDIRECT.sub(" ", command)))


def file_path_is_protected(file_path: str, agent=None) -> bool:
    """True if a file edit targets a protected file."""
    return any(frag in file_path for frag in protected_fragments(agent))


def file_path_is_mcp_config(file_path: str, agent=None) -> bool:
    """True if the path is an MCP server config of the running agent or of any agent agent_formats.json knows."""
    if Path(file_path).name in getattr(_agent(agent), "MCP_CONFIG_NAMES", ()):
        return True
    import agent_config
    return any(kind == "mcp" for _, kind, _ in agent_config.specs_for(file_path))
