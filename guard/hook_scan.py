"""
AegisPilot - agent hooks, scanned when they are registered (2026-10-23).

A hook is a command the agent runs by itself on every matching event (every tool call, every session start), so a new
hook is code that will run again and again without anyone typing it. Three ways one arrives:

  settings       an Edit/Write that adds hook commands to any agent's hook settings (agent_formats.json "hooks":
                 Claude Code settings.json, Codex hooks.json; only the commands that are new are read)
  hook scripts   a file written under any agent's hooks folder (.claude/hooks/, .codex/hooks/): its new text
  plugins        a plugin's hooks/hooks.json (plugin_scan hands the commands here)

What is read: the command line itself (shell rules; the code of `python -c` / `node -e` with the Python / JavaScript
rules) and the script files it runs (`python3 ~/.claude/hooks/x.py`, `${CLAUDE_PLUGIN_ROOT}/hooks/run.sh`), as a bundle.
The decision is the install decision's (guard_core._scan_config_write -> check_parsed); this module never decides.
"""
from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path

_CODE_SUFFIXES = (".py", ".sh", ".bash", ".js", ".mjs", ".cjs")


def commands_in(doc) -> list[dict]:
    """[{event, matcher, command}] of a settings / hooks.json document ({"hooks": {event: [{matcher, hooks: [...]}]}})."""
    hooks = doc.get("hooks") if isinstance(doc, dict) else None
    out = []
    for event, groups in (hooks or {}).items() if isinstance(hooks, dict) else []:
        for g in groups if isinstance(groups, list) else []:
            for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
                cmd = h.get("command") if isinstance(h, dict) else None
                if isinstance(cmd, str) and cmd.strip():
                    out.append({"event": str(event), "matcher": str(g.get("matcher", "")), "command": cmd})
    return out


def added_commands(old_text: str | None, new_text: str | None) -> list[dict] | None:
    """Hook commands in new_text that old_text did not have; None when new_text cannot be read as JSON."""
    try:
        new = json.loads(new_text) if new_text is not None else None
    except ValueError:
        return None
    if new is None:
        return None
    try:
        old = json.loads(old_text) if old_text else {}
    except ValueError:
        old = {}
    before = {c["command"] for c in commands_in(old)}
    return [c for c in commands_in(new) if c["command"] not in before]


def _expand(token: str, roots: dict[str, str]) -> str:
    for var, val in roots.items():
        token = token.replace("${" + var + "}", val).replace("$" + var, val)
    return os.path.expanduser(token)


def inline_code(command: str) -> dict[str, str]:
    """Code written in the command line: {"inline.py": …} for python -c, {"inline.js": …} for node -e."""
    from install_parse import _python_inline_code
    from sources.npm import inline_node_code
    out = {}
    try:
        toks = shlex.split(command)
    except ValueError:
        return out
    for i in range(len(toks)):
        py = _python_inline_code(toks[i:])
        if py:
            out["inline.py"] = py
            break
    js = inline_node_code(command)
    if js:
        out["inline.js"] = js
    return out


def scripts_of(command: str, roots: dict[str, str], cwd: str | Path | None) -> list[Path]:
    """Script files the command runs: any token that names an existing code file (after ${CLAUDE_PLUGIN_ROOT},
    $CLAUDE_PROJECT_DIR and ~ are filled in)."""
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    out = []
    for t in toks:
        p = Path(_expand(t, roots))
        if not p.is_absolute() and cwd is not None:
            p = Path(cwd) / p
        if p.suffix.lower() in _CODE_SUFFIXES and p.is_file() and p not in out:
            out.append(p)
    return out


def bundle_for(commands: list[dict], label: str, roots: dict[str, str], cwd) -> dict:
    """A Parsed.bundles entry: the command lines (and their inline code) as texts, the scripts they run as paths."""
    texts, paths = {}, []
    for i, c in enumerate(commands, 1):
        cmd = _expand(c["command"], roots)
        texts[f"hook{i}.{re.sub(r'[^A-Za-z]', '', c['event'])[:30] or 'event'}.sh"] = cmd
        for name, code in inline_code(cmd).items():
            texts[f"hook{i}.{name}"] = code
        paths += [p for p in scripts_of(cmd, roots, cwd) if p not in paths]
    short = re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-")[:60] or "hook"
    return {"name": short, "label": label, "kind": "hook", "paths": [str(p) for p in paths], "texts": texts}


def parsed_for_write(file_path: str, proposed_text: str | None, project_dir: str):
    """install_parse.Parsed for the hook code a write adds - new commands in any agent's hook settings
    (agent_formats.json "hooks"), or a script written into any agent's hooks folder - else None."""
    import agent_config
    from install_parse import Parsed
    specs = [s for _, kind, s in agent_config.specs_for(file_path) if kind == "hooks"]
    if specs:
        try:
            old_text = Path(file_path).read_text()
        except OSError:
            old_text = ""
        before, after, project_vars = set(), [], []
        for agent, kind, spec in agent_config.specs_for(file_path):
            if kind != "hooks":
                continue
            project_vars += agent_config.vars_of("project_dir", agent)
            new_doc = agent_config.parse(proposed_text, spec["format"])
            if new_doc is None:
                continue
            before |= {c["command"] for c in agent_config.hook_commands(agent_config.parse(old_text, spec["format"]) or {}, spec)}
            after += [c for c in agent_config.hook_commands(new_doc, spec) if c not in after]
        new = [c for c in after if c["command"] not in before]
        if not new:
            return None
        parsed = Parsed()
        parsed.bundles.append(bundle_for(new, f"hooks in {Path(file_path).name}", {v: project_dir for v in project_vars}, project_dir))
        return parsed
    if agent_config.in_hook_dir(file_path):
        return parsed_for_script(file_path, proposed_text)
    return None


def parsed_for_script(file_path: str, proposed_text: str | None):
    """install_parse.Parsed for a script written into a hooks folder (its new text), or None."""
    from install_parse import Parsed
    if proposed_text is None or not file_path.lower().endswith(_CODE_SUFFIXES):
        return None
    parsed = Parsed()
    name = Path(file_path).name
    parsed.bundles.append({"name": re.sub(r"[^A-Za-z0-9._-]+", "-", name)[:60] or "hook", "label": f"hook script {name}",
                           "kind": "hook", "paths": [], "texts": {name: proposed_text}})
    return parsed
