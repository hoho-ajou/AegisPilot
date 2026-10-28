"""
AegisPilot - system install: the guard out of the agent's reach.

Installed in the user's folders, everything the guard checks itself with (its files, the checksums, the check) can be
rewritten by anything that runs as that user - the agent included. A system install moves the trust anchor out of
reach: an agent running as the developer cannot change root-owned files without sudo.

  1. this build must match its own checksums (a changed build is not installed)
  2. copied to PREFIX (default /opt/aegis-pilot), owned by root, directories 0755, files 0644
  3. compiled there as root (python3 -m compileall): users cannot write __pycache__ there, so nobody can plant a .pyc and
     the hooks do not recompile on every call
  4. Claude Code's hooks pinned in managed settings: a drop-in /etc/claude-code/managed-settings.d/aegis-pilot.json
     (merged with the organisation's own managed settings; hooks in user / project settings cannot remove it).
     --managed-hooks-only also sets allowManagedHooksOnly (only managed hooks run - this turns off every other hook)
  5. /etc/aegis/config.json for the administrator's switches (switches.py), if there is none

Paths per Claude Code's documentation (code.claude.com/docs/en/managed-settings, read 2026-10-23): Linux / WSL
/etc/claude-code/, macOS /Library/Application Support/ClaudeCode/. On WSL /etc/claude-code is user-writable, so it is
not out of reach there. Codex has no documented system-wide hook location here; its hooks stay per user / project.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

GUARD_DIR = Path(__file__).resolve().parent
DEFAULT_PREFIX = Path("/opt/aegis-pilot")
CLAUDE_MANAGED = {"linux": Path("/etc/claude-code"), "darwin": Path("/Library/Application Support/ClaudeCode")}
DROPIN_NAME = "aegis-pilot.json"
SKIP = {"__pycache__", "aegis_manifest.json", ".aegis"}


class InstallError(Exception):
    pass


def _under(root: Path | None, p: Path) -> Path:
    """A system path, moved under `root` for a test / inspection run."""
    return root / p.relative_to("/") if root else p


def managed_hooks(prefix: Path) -> dict:
    import guard_cli
    hook = lambda script: {"type": "command", "command": f"python3 {guard_cli.PY_FLAGS} {prefix / 'hooks' / script}",  # noqa: E731
                           "timeout": guard_cli.HOOK_TIMEOUT_SECONDS}
    return {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [hook("pretooluse_check.py")]},
                                     {"matcher": "Edit|MultiEdit|Write", "hooks": [hook("pretooluse_editwrite_check.py")]}]}}


def plan(prefix: Path = DEFAULT_PREFIX, root: Path | None = None, managed_hooks_only: bool = False,
         platform: str = sys.platform) -> dict:
    """What an install would do (nothing is changed)."""
    import integrity
    findings = integrity.check_release(GUARD_DIR)
    if findings:
        raise InstallError(f"this guard differs from its build, not installing: {findings[0]} (check with verify, install from an official build)")
    managed_dir = CLAUDE_MANAGED.get("darwin" if platform == "darwin" else "linux")
    dropin = managed_hooks(prefix)
    if managed_hooks_only:
        dropin["allowManagedHooksOnly"] = True
    return {"source": str(GUARD_DIR), "prefix": str(_under(root, prefix)), "hooks_prefix": str(prefix),
            "dropin": str(_under(root, managed_dir / "managed-settings.d" / DROPIN_NAME)), "dropin_doc": dropin,
            "config": str(_under(root, Path("/etc/aegis/config.json")))}


def install(p: dict, root_owned: bool = True) -> None:
    prefix, dropin, config = Path(p["prefix"]), Path(p["dropin"]), Path(p["config"])
    new = prefix.with_name(prefix.name + ".installing")
    shutil.rmtree(new, ignore_errors=True)
    shutil.copytree(GUARD_DIR, new, ignore=shutil.ignore_patterns(*SKIP))
    subprocess.run([sys.executable, "-m", "compileall", "-q", str(new)], check=True)
    for d, dirs, files in os.walk(new):
        os.chmod(d, 0o755)
        for f in files:
            os.chmod(os.path.join(d, f), 0o644)
        if root_owned:
            os.chown(d, 0, 0)
            for f in files:
                os.chown(os.path.join(d, f), 0, 0)
    old = prefix.with_name(prefix.name + ".old")
    shutil.rmtree(old, ignore_errors=True)
    if prefix.exists():
        prefix.rename(old)
    new.rename(prefix)
    shutil.rmtree(old, ignore_errors=True)
    for path, doc, keep in ((dropin, p["dropin_doc"], False), (config, {"env": {}}, True)):
        if keep and path.exists():
            continue                                     # the administrator's own switches stay
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
        os.chmod(path, 0o644)
        if root_owned:
            os.chown(path, 0, 0)


def uninstall(prefix: Path = DEFAULT_PREFIX, root: Path | None = None, platform: str = sys.platform) -> list[str]:
    managed_dir = CLAUDE_MANAGED.get("darwin" if platform == "darwin" else "linux")
    removed = []
    for path in (_under(root, managed_dir / "managed-settings.d" / DROPIN_NAME), _under(root, prefix)):
        if path.is_dir():
            shutil.rmtree(path)
            removed.append(str(path))
        elif path.exists():
            path.unlink()
            removed.append(str(path))
    return removed
