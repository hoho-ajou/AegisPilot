#!/usr/bin/env python3
"""
AegisPilot - environment Profile: what the agent can do and what it can reach, collected without reading secrets.

The attack paths need two node kinds from the environment:
  principals  who code runs as - the OS user (install-time and startup code), the agent with its permission rules
  assets      what an attacker would want - private keys, cloud/registry credentials, .env files, the agent's own token,
              MCP server tokens, the guard's own config
This module collects them. What is agent-specific (where settings, MCP servers, skills and hooks live) comes from the
adapter (adapters/<agent>.read_agent_config); everything here is the same for every agent.

Never read: file contents of credentials. Assets are reported by existence and by whether the OS user can read them
(os.access); a .env file's variable NAMES are collected only with env_names=True. MCP server env values are never
copied - only their names and whether a literal (non-${VAR}) secret-looking value is present.

  python3 env_profile.py [--project DIR] [--env-names] [--out FILE]      (Claude Code; other agents: adapter needs read_agent_config)
"""
from __future__ import annotations

import glob
import json
import os
import pwd
import re
import stat
import sys
import time
from pathlib import Path

if str(Path(__file__).resolve().parent) not in sys.path:      # imported directly (tests); entry points place it
    sys.path.append(str(Path(__file__).resolve().parent))

SCHEMA = "aegis-env-profile/0.1"

# home-relative credential files any agent's OS user may hold: (pattern, kind, what it gives)
HOME_CREDENTIALS = [
    (".ssh/*", "ssh_private_key", "SSH access (remote servers, git push)"),
    ("*.pem", "private_key", "private key file (server access, etc.)"),
    (".claude*/.credentials.json", "agent_credentials", "Claude Code account token"),
    (".codex/auth.json", "agent_credentials", "Codex account token"),
    (".aws/credentials", "cloud_credentials", "AWS account"),
    (".config/gcloud/application_default_credentials.json", "cloud_credentials", "GCP account"),
    (".azure/msal_token_cache.json", "cloud_credentials", "Azure account"),
    (".kube/config", "cluster_credentials", "Kubernetes cluster"),
    (".docker/config.json", "registry_credentials", "container registry"),
    (".pypirc", "registry_credentials", "PyPI upload"),
    (".npmrc", "registry_credentials", "npm registry"),
    (".netrc", "generic_credentials", "logins for several hosts"),
    (".git-credentials", "git_credentials", "git remote repository"),
    (".gitconfig", "git_config", "git auth settings (credential helper, signing key)"),
    (".gnupg/private-keys-v1.d/*", "signing_key", "GPG private key (forged commit signatures)"),
    (".gnupg/secring.gpg", "signing_key", "GPG private key (forged commit signatures)"),
    (".pip/pip.conf", "registry_config", "pip index setting (index-url may hold credentials)"),
    (".config/pip/pip.conf", "registry_config", "pip index setting (index-url may hold credentials)"),
    (".config/gh/hosts.yml", "git_credentials", "GitHub CLI token"),
]
PROJECT_SECRETS = [(".env", "env_file"), (".env.*", "env_file")]
_EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")
# files in ~/.ssh that are not private keys (installed-by-anyone credential files of every agent are assets: install-time
# code runs as the OS user, whichever agent started it; looking only at the active agent's config dir misses e.g. a
# personal Claude token or a Codex token)
_SSH_NOT_KEYS = {"known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2", "environment", "agent"}


def _display(path: Path, home: Path, project: Path) -> str:
    for base, prefix in ((project, "./"), (home, "~/")):
        try:
            return prefix + str(path.relative_to(base))
        except ValueError:
            continue
    return str(path)


def _env_names(path: Path) -> list[str]:
    """Variable names only (the part before '='); values are never kept."""
    names = []
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if line and not line.startswith("#") and "=" in line:
                name = line.split("=", 1)[0].strip()
                if name.replace("_", "").isalnum():
                    names.append(name)
    except OSError:
        pass
    return names[:50]


def asset_entry(path: Path, kind: str, gives: str, home: Path, project: Path, scope: str) -> dict:
    try:
        st = path.stat()
        mode_private = not (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO))
    except OSError:
        mode_private = None
    return {"id": f"asset:{_display(path, home, project)}", "path": _display(path, home, project), "kind": kind,
            "gives": gives, "scope": scope, "readable_by_os_user": os.access(path, os.R_OK),
            "private_mode": mode_private}


def collect_assets(project: Path, home: Path, agent, env_names: bool, env=None) -> list[dict]:
    assets, seen = [], set()

    def add(path: Path, kind: str, gives: str, scope: str):
        if path in seen or not path.is_file() or path.name.endswith(".pub"):
            return
        if kind == "ssh_private_key" and path.name in _SSH_NOT_KEYS:
            return
        seen.add(path)
        entry = asset_entry(path, kind, gives, home, project, scope)
        if kind == "env_file":
            entry["example_file"] = path.name.endswith(_EXAMPLE_SUFFIXES)
            if env_names:
                entry["variable_names"] = _env_names(path)
        assets.append(entry)

    for pattern, kind, gives in HOME_CREDENTIALS:
        for p in sorted(glob.glob(str(home / pattern))):
            add(Path(p), kind, gives, "home")
    for pattern, kind in PROJECT_SECRETS + [("*.pem", "private_key")]:
        for p in sorted(glob.glob(str(project / pattern))):
            add(Path(p), kind, "project secrets (API keys, etc.)" if kind == "env_file" else "private key file", "project")
    for p, kind, gives in agent.credential_files(project, home, os.environ if env is None else env):
        add(p, kind, gives, "agent")
    return assets


_SECRET_PREFIXES = ("ghp_", "github_pat_", "gho_", "sk-", "xox", "AKIA", "glpat-", "hf_")


def _looks_secret(value) -> bool:
    if not isinstance(value, str) or value.startswith("${") or value.startswith("$"):
        return False
    return value.startswith(_SECRET_PREFIXES) or (len(value) >= 24 and " " not in value)


def mcp_server_entry(name: str, entry: dict, scope: str, source: str) -> dict:
    """One MCP server without its secrets: what runs (command / package / url host), env var names, and whether a
    literal secret sits in the config file (an asset by itself)."""
    from urllib.parse import urlsplit
    from mcp_guard import _is_known_source, _server_source
    entry = entry if isinstance(entry, dict) else {}
    env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
    headers = entry.get("headers") if isinstance(entry.get("headers"), dict) else {}
    url = entry.get("url") if isinstance(entry.get("url"), str) else ""
    args = [a for a in entry.get("args", []) if isinstance(a, str)] if isinstance(entry.get("args"), list) else []
    out = {"id": f"mcp:{name}", "name": name, "scope": scope, "source_file": source,
           "transport": entry.get("type") or ("http" if url else "stdio"),
           "command": os.path.basename(str(entry.get("command", ""))) or None,
           "packages": [a for a in args if not a.startswith(("-", "/", ".", "~", "$"))
                         and ("@" in a or "/" in a or "mcp" in a.lower() or a.endswith("-server"))][:5],
           "url_host": (urlsplit(url).hostname if url else None),
           "env_names": sorted(env)[:20],
           "literal_secret_in_config": any(_looks_secret(v) for v in list(env.values()) + list(headers.values())),
           "known_source": _is_known_source(_server_source(entry)) if (entry.get("command") or url) else False}
    return out


def runs_as() -> dict:
    uid = os.getuid()
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        name = str(uid)
    return {"id": f"principal:os_user:{name}", "user": name, "uid": uid, "is_root": uid == 0}


_FREE_MODES = {"bypassPermissions", "dontAsk"}


def _writable(path: Path) -> bool:
    """The OS user could create or change this file (it exists and is writable, or its nearest existing parent is)."""
    p = path
    while not p.exists() and p != p.parent:
        p = p.parent
    return os.access(p, os.W_OK)


def _git_remote(project: Path) -> str | None:
    import configparser
    cfg = project / ".git" / "config"
    if not cfg.is_file():
        return None
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        cp.read_string(cfg.read_text(errors="replace"))
    except configparser.Error:
        return None
    for sec in cp.sections():
        if sec.startswith('remote "') and cp.get(sec, "url", fallback=None):
            url = cp.get(sec, "url")
            return re.sub(r"//[^@/]*@", "//", url)          # never keep credentials embedded in a remote URL
    return None


def our_capabilities(project: Path, home: Path, cfg: dict, assets: list[dict], agent_name: str) -> list[dict]:
    """What THIS environment can do and an attacker would want: besides credential files (assets), the
    agent's own powers, each MCP server, the project's code, the remote repository, and the agent's configuration.
    `reached_by`: which attacker capabilities reach it - process (code running as the OS user), file_write, file_read,
    environment_read, agent (the agent itself, steered by text it read; its permission rules apply)."""
    out = []
    perms = cfg.get("permissions") or {}
    allow = [str(a) for a in perms.get("allow", [])]
    free = perms.get("default_mode") in _FREE_MODES or any(a in ("Bash", "Bash(*)", "Bash(**)") for a in allow)
    out.append({"id": "ours:agent_commands", "kind": "agent_commands", "label": f"agent {agent_name} running commands",
                "gives": "run commands and edit files with the agent's permissions" + (" (without approval)" if free else " (after user approval)"),
                "tier": 1 if free else 2, "reached_by": ["agent"]})
    for m in cfg.get("mcp_servers", []) or []:
        where = m.get("url_host") or m.get("command") or "?"
        reached = ["agent"] + (["file_read", "process"] if m.get("literal_secret_in_config") else []) + \
                  (["environment_read", "process"] if m.get("env_names") else [])
        out.append({"id": f"ours:mcp:{m['name']}", "kind": "mcp_tool", "label": f"MCP server '{m['name']}' ({where})",
                    "gives": f"use MCP '{m['name']}' tools (connected services and data)", "tier": 1,
                    "reached_by": sorted(set(reached)), "env_names": m.get("env_names", [])[:10]})
    if _writable(project):
        out.append({"id": "ours:repo_code", "kind": "repo_code", "label": "code under development (project folder)",
                    "gives": "plant a backdoor in the code under development", "tier": 2, "reached_by": ["agent", "file_write", "process"],
                    "path": "."})
    remote = _git_remote(project)
    push_creds = [a["path"] for a in assets if a.get("kind") in ("git_credentials", "ssh_private_key") and a.get("readable_by_os_user")]
    if remote and push_creds:
        out.append({"id": "ours:repo_push", "kind": "repo_push", "label": f"push to remote repository ({remote[:80]})",
                    "gives": "push to the remote repository (tamper with the whole team's code)", "tier": 1, "reached_by": ["agent", "process"],
                    "via": push_creds[:3]})
    cfg_paths = [s.get("file") for s in cfg.get("sources", []) if s.get("file")]
    cfg_paths += [str(project / ".mcp.json"), str(project / ".claude" / "settings.json")]
    writable = sorted({p for p in cfg_paths if _writable(Path(p))})
    if writable:
        out.append({"id": "ours:agent_config", "kind": "agent_config", "label": "agent settings, hooks and skills",
                    "gives": "tamper with agent settings and hooks (persistence: runs in every later session)", "tier": 1,
                    "reached_by": ["agent", "file_write", "process"], "paths": writable[:5]})
    return out


def collect(project_dir: str | os.PathLike, agent=None, home: str | os.PathLike | None = None, env=None,
            env_names: bool = False) -> dict:
    if agent is None:
        from adapters import DEFAULT as agent
    env = os.environ if env is None else env
    project = Path(project_dir).resolve()
    home = Path(home).resolve() if home else Path.home()
    cfg = agent.read_agent_config(project, home, env)
    user = runs_as()
    principals = [
        {**user, "kind": "os_user",
         "note": "pip install's install code and .pth startup code run as this account. Agent permission rules do not apply"},
        {"id": f"principal:agent:{agent.NAME}", "kind": "agent", "agent": agent.NAME,
         "permissions": cfg.get("permissions", {}), "sandbox": cfg.get("sandbox"),
         "note": "permission rules apply only to tool calls the agent itself makes"},
    ]
    assets = collect_assets(project, home, agent, env_names, env)
    return {
        "schema": SCHEMA,
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "project": str(project),
        "agent": agent.NAME,
        "principals": principals,
        "assets": assets,
        "capabilities": our_capabilities(project, home, cfg, assets, agent.NAME),
        "mcp_servers": cfg.get("mcp_servers", []),
        "skills": cfg.get("skills", []),
        "hooks": cfg.get("hooks", []),
        "guard_installed": cfg.get("guard_installed", False),
        "config_sources": cfg.get("sources", []),
        "plugins": cfg.get("plugins", []),
        "project_code": _project_code(project),
        "notes": cfg.get("notes", []),
    }


def _project_code(project: Path) -> dict:
    try:
        from project_code import scan
        return scan(project)
    except Exception as e:          # the code scan is an extra; it must not take the Profile down
        return {"error": type(e).__name__}


def _fingerprint(project: Path, home: Path, env, agent) -> str:
    """What the Profile depends on, as (path, mtime, size) of every file it reads: agent settings / MCP / skills / hooks,
    credential files, the project's code. A change made outside the agent (a person editing settings, a shell command)
    changes it too, which an edit log would miss."""
    import hashlib
    from project_code import SKIP_DIRS
    paths = list(getattr(agent, "config_files", lambda *a: [])(project, home, env))     # the agent's own config locations
    for pattern, _k, _g in HOME_CREDENTIALS:
        paths += sorted(Path(p) for p in glob.glob(str(home / pattern)))
    paths += sorted(project.glob(".env*")) + sorted(project.glob("requirements*.txt")) + sorted(project.glob("*.pem"))
    for root, dirs, names in os.walk(project):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        paths += [Path(root) / n for n in names if n.endswith(".py")]
    h = hashlib.sha256(f"{agent.NAME}|{project}|{os.getuid()}".encode())
    for p in paths:
        try:
            st = p.stat()
            h.update(f"{p}|{st.st_mtime_ns}|{st.st_size}|{st.st_mode}\n".encode())
        except OSError:
            h.update(f"{p}|-\n".encode())
    return h.hexdigest()


def collect_cached(project_dir, agent=None, home=None, env=None) -> dict:
    """collect(), reused from <project>/.aegis/profile.json while the fingerprint of everything it reads is unchanged."""
    if agent is None:
        from adapters import DEFAULT as agent
    env = os.environ if env is None else env
    project = Path(project_dir).resolve()
    home = Path(home).resolve() if home else Path.home()
    cache = project / ".aegis" / "profile.json"
    fp = _fingerprint(project, home, env, agent)
    try:
        doc = json.loads(cache.read_text())
        if doc.get("fingerprint") == fp and doc.get("schema") == SCHEMA:
            doc["cache"] = "hit"
            return doc
    except (OSError, ValueError):
        pass
    doc = collect(project, agent, home=home, env=env)
    doc["fingerprint"] = fp
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        tmp = cache.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(doc, ensure_ascii=False))
        os.replace(tmp, cache)
    except OSError:
        pass
    doc["cache"] = "miss"
    return doc


def main(argv: list[str]) -> int:
    import argparse
    from adapters import get
    ap = argparse.ArgumentParser(description="Collect the agent environment Profile (secret values are never read)")
    ap.add_argument("--project", default=".")
    ap.add_argument("--agent", default=None, help="claude-code (default). Other agents need read_agent_config in their adapter")
    ap.add_argument("--env-names", action="store_true", help="also collect variable names (not values) from .env files")
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    doc = collect(a.project, get(a.agent), env_names=a.env_names)
    text = json.dumps(doc, ensure_ascii=False, indent=1)
    if a.out:
        Path(a.out).write_text(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
