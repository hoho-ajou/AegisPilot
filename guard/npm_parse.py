"""
AegisPilot - npm-family install commands: what packages a command would fetch from the npm registry.

Called by install_parse for every command segment; returns False when the segment is not an npm-family install.
Fills the shared Parsed record: Parsed.ecosystem_packages gets ("npm", name, spec) for registry packages (spec = what
was written: a version, a range, a dist-tag or None for latest), Parsed.npm_lock gets the locked versions of a project
install (for the lock-file malicious-release check), Parsed.unscanned gets what cannot be scanned (git, URLs, other
registries, local tarballs).

  npm install|i|add|ci|update [specs]      npx / npm exec / npm x <pkg>      npm init|create <x>  (runs create-<x>)
  yarn add|install|dlx|create, yarn        pnpm add|install|i|update|dlx|create, pnpx       bun add|install|x|create, bunx

A bare install (no specs) installs the project's package.json dependencies, pinned by package-lock.json when present.
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
_VALUE_FLAGS = {"--registry", "--prefix", "-C", "--cache", "--workspace", "-w", "--tag", "--userconfig", "--omit",
                "--include", "--loglevel", "--install-strategy", "--before", "--cwd", "--filter", "-F", "--dir",
                "--network-timeout", "--modules-folder", "--global-folder", "--cache-folder", "--call", "-c"}
_PACKAGE_FLAGS = {"--package", "-p"}                      # npx -p <pkg> / npm exec --package=<pkg>
DEFAULT_REGISTRY = "https://registry.npmjs.org"


def _norm_registry(url: str) -> str:
    return url.strip().strip("'\"").rstrip("/")


class _Registries(dict):
    """{"" / "@scope": registry} plus which of them the command itself chose (--registry), for index_trust.py."""

    def __init__(self, *a):
        super().__init__(*a)
        self.from_command: set[str] = set()


def _npmrc_registries(cwd: Path | None, home: Path | None) -> dict[str, str]:
    """{"": default registry, "@scope": registry} from the project's and the user's .npmrc (project wins)."""
    out: dict[str, str] = {}
    for f in ([home / ".npmrc"] if home else []) + ([cwd / ".npmrc"] if cwd else []):
        try:
            text = f.read_text(errors="replace") if f.is_file() and f.stat().st_size < 256 * 1024 else ""
        except OSError:
            text = ""
        for line in text.splitlines():
            m = re.match(r"^\s*(@[\w.-]+:)?registry\s*=\s*(\S+)", line)
            if m:
                out[(m.group(1) or "").rstrip(":")] = _norm_registry(m.group(2))
    return out


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
        origin = "command" if key in getattr(registries, "from_command", ()) else "config"
        parsed.add_unscanned("custom_index", f"{name} ← {reg}"[:160], "npm registry is not registry.npmjs.org - packages from it cannot be checked",
                             url=reg, origin=origin)
        return
    item = ("npm", name, ver)
    if item not in parsed.ecosystem_packages:
        parsed.ecosystem_packages.append(item)


def _project(cwd: Path | None, parsed, registries: dict[str, str], shown: str) -> None:
    """A bare install: package.json dependencies (+ dev/optional), pinned by package-lock.json when present."""
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


def handle(toks: list[str], parsed, cwd: Path | None, home: Path | None = None) -> bool:
    """True if `toks` is an npm-family install (parsed is filled in), False otherwise."""
    if not toks:
        return False
    head, rest = Path(toks[0]).name, toks[1:]
    tool = {"npx": "npm", "pnpx": "pnpm", "bunx": "bun"}.get(head, head)
    if tool not in _INSTALL:
        return False
    registries = _Registries(_npmrc_registries(cwd, home))
    for reg in _flag_value(rest, {"--registry"}):
        registries[""] = _norm_registry(reg)
        registries.from_command.add("")
    shown = " ".join(toks)[:120]
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
        _project(cwd, parsed, registries, shown)
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
        _project(cwd, parsed, registries, shown)
    return True
