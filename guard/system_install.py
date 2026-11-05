"""
AegisPilot - system install: the guard out of the agent's reach.

Installed in the user's folders, everything the guard checks itself with (its files, the checksums, the check) can be
rewritten by anything that runs as that user - the agent included. A system install moves the trust anchor out of
reach: an agent running as the developer cannot change root-owned files without sudo.

  0. it runs only from a root-owned copy that no other user can change (a fresh download, see FRESH_COPY): the code
     that runs as root here, checks included, is the code of that folder, so a folder the user can write could have
     been changed together with its checksums and its checks. --from-user-folder overrides this, deliberately
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


FRESH_COPY = ("sudo sh -c 'd=$(mktemp -d) && git -c advice.detachedHead=false clone -q --depth 1 --branch {tag} "
              "https://github.com/hoho-ajou/AegisPilot \"$d\" && python3 -I \"$d/guard/guard_cli.py\" system-install'")


class InstallError(Exception):
    pass


def user_writable(folder: Path) -> str | None:
    """Why a non-root user could change what runs from `folder` (None: nobody but root can): the folder, anything in it,
    or a folder above it that is not root-owned or is writable by group or others. A world-writable folder above with
    the sticky bit (/tmp) is fine: others cannot rename or remove what root owns in it."""
    import stat
    folder = Path(folder).resolve()
    for p in [*reversed(folder.parents), folder]:
        st = p.stat()
        if st.st_uid != 0:
            return f"{p} is not owned by root"
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not (p != folder and st.st_mode & stat.S_ISVTX):
            return f"{p} can be written by other users"
    for d, dirs, files in os.walk(folder):
        for name in dirs + files:
            st = os.lstat(os.path.join(d, name))
            if st.st_uid != 0 or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return f"{os.path.join(d, name)} is not root-owned or can be written by other users"
    return None


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
         platform: str = sys.platform, from_user_folder: bool = False) -> dict:
    """What an install would do (nothing is changed). root: a test / inspection run under that folder, where the
    copy's owner does not matter (nothing reaches the real system)."""
    import integrity
    if root is None and not from_user_folder:
        why = user_writable(GUARD_DIR)
        if why:
            tag = _release_tag()
            raise InstallError(f"{why}. A system install runs this folder's code as root, so it must be a copy only root "
                               f"can change. Install from a fresh download instead:\n  {FRESH_COPY.format(tag=tag)}\n"
                               "(or, knowing the folder is unchanged, add --from-user-folder)")
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


def _check_copy(new: Path) -> None:
    import integrity
    for d, dirs, files in os.walk(new):
        for name in dirs + files:
            f = Path(d) / name
            if f.is_symlink() or not (f.is_dir() or f.is_file()):
                raise InstallError(f"not installing: {f.relative_to(new)} is a link or a special file")
    findings = integrity.check_release(new)
    if findings:
        raise InstallError(f"this guard differs from its build, not installing: {findings[0]}")


def _release_tag() -> str:
    try:
        return "v" + json.loads((GUARD_DIR / ".claude-plugin" / "plugin.json").read_text())["version"]
    except (OSError, ValueError, KeyError, TypeError):
        return "v0.1.1"


def install(p: dict, root_owned: bool = True) -> None:
    prefix, dropin, config = Path(p["prefix"]), Path(p["dropin"]), Path(p["config"])
    new = prefix.with_name(prefix.name + ".installing")
    shutil.rmtree(new, ignore_errors=True)
    # links are copied as links and then refused (followed, a link to /etc/shadow would become a world-readable copy),
    # and the copy is what gets checked: the source folder is user-writable and could change after a check
    shutil.copytree(GUARD_DIR, new, ignore=shutil.ignore_patterns(*SKIP), symlinks=True)
    try:
        _check_copy(new)
    except InstallError:
        shutil.rmtree(new, ignore_errors=True)
        raise
    # -I and cwd "/": with -m, Python would first look for compileall.py in the current folder, as root
    subprocess.run([sys.executable, "-I", "-m", "compileall", "-q", str(new)], check=True, cwd="/")
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
