"""
AegisPilot - npm-family install commands: what packages a command would fetch from the npm registry.

Called by install_parse for every command segment; returns False when the segment is not an npm-family install.
Fills the shared Parsed record: Parsed.ecosystem_packages gets ("npm", name, spec) for registry packages (spec = what
was written: a version, a range, a dist-tag or None for latest), Parsed.npm_lock gets the locked versions of a project
install (for the lock-file malicious-release check), Parsed.unscanned gets what cannot be scanned (git, URLs, other
registries, local tarballs).

  npm install|i|add|ci|update [specs]      npx / npm exec / npm x <pkg>      npm init|create <x>  (runs create-<x>)
  yarn add|install|dlx|create, yarn        pnpm add|install|i|update|dlx|create, pnpx       bun add|install|x|create, bunx

A bare install (no specs) installs the project's package.json dependencies, pinned by package-lock.json when present,
and runs the project's own install scripts (preinstall / install / postinstall / prepare ...): those and the files they
run are scanned as a bundle (sources/npm.run_texts), like a package's.

Where packages come from: registry.npmjs.org unless --registry / --@scope:registry, the environment (npm_config_registry
in any case, YARN_NPM_REGISTRY_SERVER, YARN_REGISTRY, BUN_CONFIG_REGISTRY), .npmrc, .yarnrc(.yml) or bunfig.toml say
otherwise - then the packages are reported as not scanned (custom_index; index_trust.py trusts the person's own).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

MAX_PROJECT_PACKAGES = 60
_INSTALL = {"npm": {"install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall", "add",
                    "ci", "clean-install", "install-clean", "install-test", "it", "update", "up", "upgrade"},
            "yarn": {"add", "install", "upgrade", "up"},
            "pnpm": {"add", "install", "i", "update", "up", "upgrade"},
            "bun": {"add", "a", "install", "i", "update"}}
_RUNNERS = {"npx", "pnpx", "bunx"}
_RUN_SUBS = {"npm": {"exec", "x"}, "yarn": {"dlx"}, "pnpm": {"dlx"}, "bun": {"x"}}
_CREATE_SUBS = {"npm": {"init", "create", "innit"}, "yarn": {"create"}, "pnpm": {"create"}, "bun": {"create"}}
_VALUE_FLAGS = {"--registry", "--globalconfig", "--prefix", "-C", "--cache", "--workspace", "-w", "--tag", "--userconfig", "--omit",
                "--include", "--loglevel", "--install-strategy", "--before", "--cwd", "--filter", "-F", "--dir",
                "--network-timeout", "--modules-folder", "--global-folder", "--cache-folder", "--call", "-c"}
_PACKAGE_FLAGS = {"--package", "-p"}                      # npx -p <pkg> / npm exec --package=<pkg>
DEFAULT_REGISTRY = "https://registry.npmjs.org"


def _norm_registry(url: str) -> str:
    return url.strip().strip("'\"").rstrip("/")


class _Registries(dict):
    """{"" / "@scope": registry} plus who chose each (origin: "command" for --registry or a variable set in the command,
    "session_env" for the session's environment, else a config file), for index_trust.py."""

    def __init__(self, *a):
        super().__init__(*a)
        self.from_command: set[str] = set()
        self.origins: dict[str, str] = {}

    def set(self, key: str, url: str, origin: str) -> None:
        self[key] = _norm_registry(url)
        self.origins[key] = origin
        if origin == "command":
            self.from_command.add(key)


# registry settings in the environment (npm reads npm_config_* in any case; yarn and bun have their own)
_REGISTRY_ENV = {"npm_config_registry", "yarn_npm_registry_server", "yarn_registry", "bun_config_registry"}
_CONFIG_FILE_ENV = {"npm_config_userconfig", "npm_config_globalconfig", "yarn_rc_filename"}
_CONFIG_FILE_FLAGS = {"--userconfig", "--globalconfig"}


def _read_small(f: Path) -> str:
    try:
        return f.read_text(errors="replace") if f.is_file() and f.stat().st_size < 256 * 1024 else ""
    except OSError:
        return ""


def _npmrc_registries(cwd: Path | None, home: Path | None, tool: str = "npm") -> dict[str, str]:
    """{"": default registry, "@scope": registry} from the project's and the user's .npmrc (project wins), and for yarn
    its .yarnrc / .yarnrc.yml, for bun its bunfig.toml."""
    out: dict[str, str] = {}
    dirs = ([home] if home else []) + ([cwd] if cwd else [])
    for d in dirs:
        for line in _read_small(d / ".npmrc").splitlines():
            m = re.match(r"^\s*(@[\w.-]+:)?registry\s*=\s*(\S+)", line)
            if m:
                out[(m.group(1) or "").rstrip(":")] = _norm_registry(m.group(2))
        if tool == "yarn":
            for line in _read_small(d / ".yarnrc").splitlines():          # yarn 1: registry "URL", "@s:registry" "URL"
                m = re.match(r"^\s*\"?(@[\w.-]+:)?registry\"?\s+\"?([^\s\"]+)", line)
                if m:
                    out[(m.group(1) or "").rstrip(":")] = _norm_registry(m.group(2))
            scope = None
            for line in _read_small(d / ".yarnrc.yml").splitlines():      # yarn 2+: npmRegistryServer, npmScopes.<s>
                m = re.match(r"^(\s*)npmRegistryServer:\s*[\"']?([^\s\"']+)", line)
                s = re.match(r"^\s{2,4}[\"']?@?([\w.-]+)[\"']?:\s*$", line)
                if s:
                    scope = "@" + s.group(1)
                elif not line.startswith(" "):
                    scope = None
                if m:
                    out[scope if m.group(1) and scope else ""] = _norm_registry(m.group(2))
        if tool == "bun":
            section = ""
            for line in _read_small(d / "bunfig.toml").splitlines():
                h = re.match(r"^\s*\[([^\]]+)\]", line)
                if h:
                    section = h.group(1).strip()
                    continue
                m = re.match(r"^\s*(\"?[@\w.-]+\"?)\s*=\s*(?:\{[^}]*url\s*=\s*)?[\"']([^\"']+)", line)
                if m and section == "install" and m.group(1) == "registry":
                    out[""] = _norm_registry(m.group(2))
                elif m and section == "install.scopes":
                    out["@" + m.group(1).strip('"').lstrip("@")] = _norm_registry(m.group(2))
    return out


def _env_registries(registries: _Registries, env: dict | None, origin: str, parsed) -> None:
    for key, value in (env or {}).items():
        k = str(key).lower()
        if k in _REGISTRY_ENV and value:
            registries.set("", str(value), origin)
        elif k in _CONFIG_FILE_ENV and value and origin == "command":
            parsed.add_unscanned("custom_index", f"{key}={value}"[:160],
                                 "another npm config file set by an environment variable can change where packages come from")


def split_spec(spec: str) -> tuple[str | None, str | None, str | None]:
    """(name, version spec, why not scannable). `x`, `x@1.2`, `@s/x@^1`, `a@npm:x@1` -> registry; git/URL/path -> why."""
    s = spec.strip().strip("'\"")
    m = re.match(r"^(@?[^@\s]+)@npm:(.+)$", s)                  # alias: name@npm:real@spec
    if m:
        s = m.group(2)
    if re.match(r"^(git\+|git:|git@|github:|gitlab:|bitbucket:|gist:)", s) or re.match(r"^https?://", s):
        return None, None, "an npm package from git or a URL cannot be checked as a registry package"
    if s.startswith(("file:", "link:", "./", "../", "/", "~")) or s.endswith((".tgz", ".tar.gz")) or s.startswith("workspace:"):
        return None, None, "a local npm package (folder or tgz) cannot be checked as a registry package"
    if re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s):                # user/repo = GitHub shorthand
        return None, None, "an npm package from a GitHub repository cannot be checked as a registry package"
    m = re.match(r"^(@[^/@\s]+/[^@\s]+|[^@\s]+)(?:@(.*))?$", s)
    if not m:
        return None, None, "could not parse the npm package name"
    return m.group(1), (m.group(2) or None), None


def _positionals(args: list[str]) -> list[str]:
    out, i = [], 0
    while i < len(args):
        t = args[i]
        if t == "--":
            out += args[i + 1:]
            break
        if t in _VALUE_FLAGS:
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        out.append(t)
        i += 1
    return out


def _flag_value(args: list[str], names: set) -> list[str]:
    vals = []
    for i, t in enumerate(args):
        if t in names and i + 1 < len(args):
            vals.append(args[i + 1])
        for n in names:
            if t.startswith(n + "="):
                vals.append(t.split("=", 1)[1])
    return vals


def _add(parsed, spec: str, registries: dict[str, str], shown: str) -> None:
    name, ver, why = split_spec(spec)
    if why:
        from sources import direct
        src = direct.parse_npm(spec)
        if src is not None:                      # a git repository / tarball URL: fetched and scanned (sources/direct.py)
            if src not in parsed.direct_sources:
                parsed.direct_sources.append(src)
            return
        parsed.add_unscanned("requirements_unreadable" if "local" in why else "vcs_or_url", spec[:120], why)
        return
    from sources import npm
    if not npm.valid_name(name):
        parsed.add_unscanned("unparsed", spec[:120], "could not parse the npm package name (variables, substitution, etc.)")
        return
    scope = name.split("/")[0] if name.startswith("@") else ""
    reg = registries.get(scope) or registries.get("") or DEFAULT_REGISTRY
    if _norm_registry(reg) != DEFAULT_REGISTRY:
        key = scope if scope in registries else ""
        origin = getattr(registries, "origins", {}).get(key) or ("command" if key in getattr(registries, "from_command", ()) else "config")
        parsed.add_unscanned("custom_index", f"{name} ← {reg}"[:160], "npm registry is not registry.npmjs.org - packages from it cannot be checked",
                             url=reg, origin=origin)
        return
    item = ("npm", name, ver)
    if item not in parsed.ecosystem_packages:
        parsed.ecosystem_packages.append(item)


def _project(cwd: Path | None, parsed, registries: dict[str, str], shown: str, scripts: bool = True) -> None:
    """A bare install: package.json dependencies (+ dev/optional), pinned by package-lock.json when present, and the
    project's own install scripts (unless scripts is False: --ignore-scripts)."""
    if cwd is None:
        parsed.add_unscanned("requirements_unreadable", shown, "working folder unknown, so package.json was not checked")
        return
    try:
        doc = json.loads((cwd / "package.json").read_text(errors="replace"))
    except FileNotFoundError:
        return                                         # npm fails without a package.json: nothing is installed
    except (OSError, ValueError):
        parsed.add_unscanned("requirements_unreadable", "package.json", "could not read package.json")
        return
    if "package.json" in parsed.written:
        parsed.add_unscanned("requirements_unreadable", "package.json", "the same command writes package.json - its contents are unknown before it runs")
        return
    if scripts:
        _project_scripts(cwd, doc if isinstance(doc, dict) else {}, parsed)
    pins: dict[str, str] = {}
    try:
        lock = json.loads((cwd / "package-lock.json").read_text(errors="replace"))
        from sources import npm
        parsed.npm_lock_scripts = npm.lock_install_scripts(lock)     # dependencies whose install scripts npm will run
        for path, info in (lock.get("packages") or {}).items():
            if path.startswith("node_modules/") and isinstance(info, dict) and info.get("version") and not info.get("link"):
                name = path.rsplit("node_modules/", 1)[1]
                if path.count("node_modules/") == 1:   # a top-level entry pins a direct dependency
                    pins.setdefault(name, str(info["version"]))
                parsed.npm_lock.append((name, str(info["version"])))
    except (OSError, ValueError, AttributeError):
        pass
    deps: dict = {}
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        if isinstance(doc.get(key), dict):
            deps.update(doc[key])
    for i, (name, spec) in enumerate(deps.items()):
        if i >= MAX_PROJECT_PACKAGES:
            parsed.add_unscanned("too_many_packages", f"only {MAX_PROJECT_PACKAGES} of {len(deps)} package.json dependencies checked",
                                 "too many dependencies: some were not checked")
            break
        spec = str(spec)
        if name in pins:
            _add(parsed, f"{name}@{pins[name]}", registries, shown)
        elif split_spec(spec)[2]:                       # git / file / URL dependency
            _add(parsed, spec, registries, shown)
        else:
            _add(parsed, f"{name}@{spec}", registries, shown)
    parsed.project_installs.append(str(cwd))


def _project_scripts(cwd: Path, doc: dict, parsed) -> None:
    """A project install runs the project's own install scripts (npm, yarn, pnpm and bun all do): the commands, the files
    they run and node-gyp's command expansions are scanned as a bundle. What cannot be read is a REVIEW."""
    from sources import npm
    try:
        runs = npm.install_runs(cwd, doc, npm.PROJECT_EVENTS)
        texts, notes = npm.run_texts(cwd, doc, npm.PROJECT_EVENTS)
    except Exception as e:                               # never a silent pass over scripts that will run
        parsed.add_unscanned("requirements_unreadable", "package.json scripts", f"could not read the project's install scripts: {type(e).__name__}")
        return
    named = {Path(n).name for n in runs.named} | {Path(rel).name for _, rel, _ in runs.files}
    if named & parsed.written:
        parsed.add_unscanned("requirements_unreadable", ", ".join(sorted(named & parsed.written))[:120],
                             "the same command writes a file the project's install scripts run - its contents are unknown before it runs")
    for note in notes:
        parsed.add_unscanned("requirements_unreadable", note[:120], "a file the project's install scripts run could not be checked")
    if texts:
        name = doc.get("name") if isinstance(doc.get("name"), str) and doc.get("name") else cwd.name or "project"
        bundle = {"name": re.sub(r"[^A-Za-z0-9._@/-]+", "-", name)[:60], "label": f"install scripts of {name} (package.json)"[:120],
                  "kind": "project_scripts", "paths": [], "texts": texts}
        if bundle not in parsed.bundles:
            parsed.bundles.append(bundle)


def _create_package(initializer: str) -> str:
    """`npm init vite` runs create-vite, `npm init @scope` runs @scope/create, `@scope/x` runs @scope/create-x."""
    if re.fullmatch(r"@[\w.-]+", initializer):
        return f"{initializer}/create"
    name, ver, _ = split_spec(initializer)
    if not name:
        return initializer
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        pkg = f"{scope}/create" + (f"-{rest}" if rest else "")
    else:
        pkg = f"create-{name}"
    return f"{pkg}@{ver}" if ver else pkg


def _ignore_scripts(rest: list[str], env: dict | None) -> bool:
    """`--ignore-scripts` (or npm_config_ignore_scripts=true in the command): the project's install scripts do not run."""
    flag = [a for a in rest if a == "--ignore-scripts" or a.startswith("--ignore-scripts=")]
    if flag:
        return flag[-1] in ("--ignore-scripts", "--ignore-scripts=true")
    return any(str(k).lower() == "npm_config_ignore_scripts" and str(v).lower() == "true" for k, v in (env or {}).items())


def _scope_registry_flags(rest: list[str], registries: _Registries) -> list[str]:
    """`--@scope:registry=URL` / `--@scope:registry URL`: set the scope's registry and drop the flag (and its value)."""
    out, i = [], 0
    while i < len(rest):
        m = re.match(r"^--(@[\w.-]+):registry(?:=(.*))?$", rest[i])
        if m:
            value = m.group(2) if m.group(2) is not None else (rest[i + 1] if i + 1 < len(rest) else "")
            if value:
                registries.set(m.group(1), value, "command")
            i += 1 if m.group(2) is not None else 2
            continue
        out.append(rest[i])
        i += 1
    return out


def handle(toks: list[str], parsed, cwd: Path | None, home: Path | None = None, env: dict | None = None,
           session_env: dict | None = None) -> bool:
    """True if `toks` is an npm-family install (parsed is filled in), False otherwise. env: variables the command sets
    (`npm_config_registry=URL npm i x`, an earlier `export`); session_env: the environment the session runs in."""
    if not toks:
        return False
    head, rest = Path(toks[0]).name, toks[1:]
    tool = {"npx": "npm", "pnpx": "pnpm", "bunx": "bun"}.get(head, head)
    if tool not in _INSTALL:
        return False
    shown = " ".join(toks)[:120]
    registries = _Registries(_npmrc_registries(cwd, home, tool))
    _env_registries(registries, session_env, "session_env", parsed)
    _env_registries(registries, env, "command", parsed)
    rest = _scope_registry_flags(rest, registries)
    for reg in _flag_value(rest, {"--registry"}):
        registries.set("", reg, "command")
    for cfg in _flag_value(rest, _CONFIG_FILE_FLAGS):
        parsed.add_unscanned("custom_index", f"npm config file {cfg}"[:160], "another npm config file can change where packages come from")
    if head in _RUNNERS or (rest and rest[0] in _RUN_SUBS.get(tool, ())):
        args = rest if head in _RUNNERS else rest[1:]
        pkgs = _flag_value(args, _PACKAGE_FLAGS)
        pos = _positionals([a for a in args if not any(a == f or a.startswith(f + "=") for f in _PACKAGE_FLAGS)])
        if not pkgs and pos:
            first = pos[0]
            name = split_spec(first)[0]
            if cwd is not None and name and (cwd / "node_modules" / ".bin" / name.split("/")[-1]).exists():
                return True                            # npx runs the project's own installed copy: nothing is fetched
            pkgs = [first]
        parsed.installs = True
        for p in pkgs:
            _add(parsed, p, registries, shown)
        return True
    if rest and rest[0] in _CREATE_SUBS.get(tool, ()):
        pos = _positionals(rest[1:])
        if tool == "npm" and rest[0] == "init" and not pos:
            return True                                # plain `npm init` writes a package.json, installs nothing
        if pos:
            parsed.installs = True
            _add(parsed, _create_package(pos[0]), registries, shown)
        return True
    if tool == "yarn" and (not rest or (rest[0].startswith("-") and not _positionals(rest))):
        parsed.installs = True                          # bare `yarn` = yarn install
        _project(cwd, parsed, registries, shown, not _ignore_scripts(rest, env))
        return True
    if rest and rest[0] == "global" and tool == "yarn":
        rest = rest[1:]
    if not rest or rest[0] not in _INSTALL[tool]:
        return False
    specs = _positionals(rest[1:])
    parsed.installs = True
    if specs and rest[0] not in ("ci", "clean-install", "install-clean"):
        for spec in specs:
            _add(parsed, spec, registries, shown)
    else:
        _project(cwd, parsed, registries, shown, not _ignore_scripts(rest, env))
    return True
