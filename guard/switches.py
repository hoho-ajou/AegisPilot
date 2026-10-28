"""
AegisPilot - environment switches that can only make the guard weaker (2026-10-23).

Some AEGIS_* variables exist for tests and slow machines: another rules folder, rule modules off (rule_modules.py), MCP /
plugin / hook scanning off, another
"system" policy file, a shorter hook deadline (a timed-out hook lets the command through), another artifact choice, the
verdict cache. Set in the environment of a built guard, each would be a quiet way around it - an agent that writes
`export AEGIS_RULES_DIR=...` into ~/.bashrc changes every later session.

So in a built guard (BUILD_INFO.json next to the code) these are read from a settings file, never the environment
(2026-10-23: switching a check on or off is a file setting):
  /etc/aegis/config.json {"env": {"AEGIS_...": "..."}}  honoured when it is owned by root and not writable by group or
                                                      others (an administrator's choice, out of the agent's reach); wins
  ~/.aegis/config.json   the same format, for a guard installed in the user's folders: a protected path (".aegis/",
                        guard_paths.GUARD_FRAGMENTS), so an agent that writes it is stopped like one that edits the guard.
                        Not read by a system install (a guard the user cannot write): there only the administrator decides.
In a development checkout the environment works as before (the tests use it).
Switches that do not weaken anything (AEGIS_MODE, AEGIS_FAIL_CLOSED, AEGIS_ML ...) are read from the environment as usual.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

GUARD_DIR = Path(__file__).resolve().parent
SYSTEM_CONFIG = Path("/etc/aegis/config.json")
USER_CONFIG = Path.home() / ".aegis" / "config.json"
WEAKENING = ("AEGIS_RULES_DIR", "AEGIS_MCP_SCAN", "AEGIS_SYSTEM_POLICY", "AEGIS_HOOK_DEADLINE_SECONDS",
             "AEGIS_ARTIFACT_POLICY", "AEGIS_CACHE", "AEGIS_RULE_MODULES")


def released() -> bool:
    return (GUARD_DIR / "BUILD_INFO.json").exists()


def _system_env(path: Path = SYSTEM_CONFIG) -> dict:
    """The "env" of the system configuration, or {} when it is missing or not trustworthy (not root-owned, writable by
    group or others)."""
    try:
        st = path.stat()
        if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return {}
        env = json.loads(path.read_text()).get("env")
        return {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def _user_env(path: Path | None = None) -> dict:
    """The "env" of ~/.aegis/config.json, or {} when it is missing or unreadable, or when this guard is a system install."""
    if not os.access(GUARD_DIR, os.W_OK):
        return {}                                        # root-owned guard: the user's file does not override it
    try:
        env = json.loads((path or USER_CONFIG).read_text()).get("env")
        return {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def file_env() -> dict:
    return {**_user_env(), **_system_env()}


def get(name: str, default: str | None = None) -> str | None:
    """os.environ.get for every switch, except the weakening ones in a built guard: those come from the settings files."""
    if name in WEAKENING and released():
        return file_env().get(name, default)
    return os.environ.get(name, default)


def ignored() -> list[str]:
    """Weakening switches set in the environment that a built guard does not follow (shown by guard_cli verify)."""
    if not released():
        return []
    env = file_env()
    return [n for n in WEAKENING if n in os.environ and env.get(n) != os.environ[n]]
