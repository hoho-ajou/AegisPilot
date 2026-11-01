"""
AegisPilot - npm packages as a source: registry metadata, version ranges, the tarball.

What npm would install is read the way pip's is: the registry's metadata picks the version (an exact version, a
dist-tag such as `latest`, or a semver range like `^1.2.0`), the tarball is downloaded and unpacked with the same limits
as a wheel (safe_extract), and nothing in it is run. npm runs a package's own code at install through its lifecycle
scripts (package.json "preinstall", "install", "postinstall"); those commands are written next to the files as
`package.json#<event>.sh` so the shell rules read them like any other file, and what they run (a script followed through
`npm run`, a file `node`/`sh`/`python` is given, a Makefile, node-gyp's command expansions) is written next to them.

Not here: dependencies of the package (npm installs the whole tree and runs their lifecycle scripts too - see
transitive_malicious for the lock-file check), registries other than registry.npmjs.org (reported as unscanned).
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.npmjs.org"
TIMEOUT = 20
MAX_TARBALL_BYTES = 200 * 1024 * 1024
LIFECYCLE = ("preinstall", "install", "postinstall")        # run when the package is installed as a dependency
# file types kept from the tarball: JavaScript, package.json, scripts the lifecycle may call, text an agent reads, and the
# native build files an install runs (node-gyp's .gyp/.gypi, Makefiles). Files the scripts name are kept whatever their
# suffix (extract).
KEEP_SUFFIXES = (".js", ".mjs", ".cjs", ".json", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".py", ".md", ".gyp", ".gypi",
                 ".mk", "/makefile", "/gnumakefile")
_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.I)


def valid_name(name: str) -> bool:
    return bool(_NAME.match(name or "")) and len(name) <= 214


def metadata(name: str) -> dict:
    """The registry's abbreviated document (versions, dist-tags, tarball URLs) - what npm itself reads to install."""
    url = f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.npm.install-v1+json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


# --------------------------------------------------------------------------------------------- semver (npm's subset)

_VER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def parse(v: str):
    """(major, minor, patch, prerelease) or None. A release sorts above its prereleases."""
    m = _VER.match(v.strip())
    if not m:
        return None
    pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split(".")) if m.group(4) else None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _key(p):
    pre = p[3]
    # numeric identifiers sort below alphanumeric ones (semver 11.4.4); no prerelease sorts above any prerelease
    return (p[0], p[1], p[2], 1, ()) if pre is None else \
        (p[0], p[1], p[2], 0, tuple((0, x, "") if isinstance(x, int) else (1, 0, x) for x in pre))


def _partial(v: str):
    """'1', '1.2', '1.x', '1.2.3-rc.1' -> (parts with None for a wildcard, prerelease)."""
    v = v.strip().lstrip("v=")
    if v in ("", "*", "x", "X"):
        return [None, None, None], None
    core, _, pre = v.partition("-")
    core = core.split("+")[0]
    bits = core.split(".")
    if len(bits) > 3 or not all(b.isdigit() or b in ("x", "X", "*") for b in bits):
        raise ValueError(v)
    parts = [int(b) if b.isdigit() else None for b in bits] + [None] * (3 - len(bits))
    for i in range(1, 3):                       # 1.x.3 -> 1.x.x
        if parts[i - 1] is None:
            parts[i] = None
    return parts, (pre or None)


def _bounds(op: str, v: str) -> list[tuple[str, tuple]]:
    """A comparator as a list of (operator, key) bounds."""
    parts, pre = _partial(v)
    M, m, p = parts
    lo = (M or 0, m or 0, p or 0)
    full = lambda a: parse(".".join(map(str, a)) + (f"-{pre}" if pre and None not in parts else ""))  # noqa: E731
    floor = lambda a: _key((*a, (0,)))          # the lowest prerelease: "<2.0.0-0"  # noqa: E731
    if M is None:
        return [] if op in ("", "=", ">=", "<=") else [("<", floor((0, 0, 0)))] if op == "<" else []
    if op == "^":
        if M > 0 or m is None:
            hi = (M + 1, 0, 0)
        elif m > 0 or p is None:
            hi = (0, m + 1, 0)
        else:
            hi = (0, 0, p + 1)
        return [(">=", _key(full(lo))), ("<", floor(hi))]
    if op == "~":
        hi = (M + 1, 0, 0) if m is None else (M, m + 1, 0)
        return [(">=", _key(full(lo))), ("<", floor(hi))]
    if None in parts:                           # 1.2 / 1.x with = or a comparison
        hi = (M + 1, 0, 0) if m is None else (M, m + 1, 0)
        return {"": [(">=", _key(full(lo))), ("<", floor(hi))], "=": [(">=", _key(full(lo))), ("<", floor(hi))],
                ">=": [(">=", _key(full(lo)))], "<": [("<", floor(lo))], ">": [(">=", floor(hi))],
                "<=": [("<", floor(hi))]}[op]
    k = _key(full(lo))
    return [("==", k)] if op in ("", "=") else [(op, k)]


def _range_sets(spec: str) -> list[tuple[list, bool]]:
    """`^1.2 || >=3 <4` -> [(bounds, allows_prerelease), ...]."""
    out = []
    for alt in spec.split("||"):
        alt = alt.strip()
        m = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alt)          # hyphen range: 1.2.3 - 2.3 means >=1.2.3 <2.4.0-0
        if m:
            hi = m.group(2)
            upper = [b for b in _bounds("", hi) if b[0] == "<"] if None in _partial(hi)[0] else _bounds("<=", hi)
            out.append((_bounds(">=", m.group(1)) + upper, "-" in alt.replace(" - ", " ")))
            continue
        bounds = []
        for tok in re.findall(r"(>=|<=|>|<|=|\^|~>?|)\s*([^\s<>=^~]+)", alt) if alt else [("", "*")]:
            op, v = tok
            bounds += _bounds("~" if op == "~>" else op, v)
        out.append((bounds, "-" in alt))           # a range naming a prerelease lets prereleases match (simplified)
    return out


def satisfies(version: str, spec: str) -> bool:
    p = parse(version)
    if p is None:
        return False
    k = _key(p)
    for bounds, allow_pre in _range_sets(spec):
        if p[3] is not None and not allow_pre:
            continue
        ok = True
        for op, b in bounds:
            if not {"==": k == b, ">=": k >= b, ">": k > b, "<": k < b, "<=": k <= b}[op]:
                ok = False
                break
        if ok:
            return True
    return False


def pick_version(meta: dict, spec: str | None) -> str | None:
    """The version npm installs for `spec`: a dist-tag (default `latest`), an exact version, else the highest that
    satisfies the range. None if nothing matches or the spec cannot be read."""
    tags = meta.get("dist-tags") or {}
    versions = list((meta.get("versions") or {}).keys())
    spec = (spec or "").strip()
    if spec in ("", "*", "latest") or spec in tags:
        tagged = tags.get(spec or "latest")
        if tagged in versions:
            return tagged
        if spec in ("", "*", "latest") and not tagged:
            spec = "*"
        elif spec not in ("", "*"):
            return None
    if spec in versions:
        return spec
    latest = tags.get("latest")
    try:
        if latest in versions and satisfies(latest, spec):      # npm prefers the `latest` tag when it fits the range
            return latest
        good = [v for v in versions if satisfies(v, spec)]
    except (ValueError, KeyError):
        return None
    return max(good, key=lambda v: _key(parse(v))) if good else None


# ----------------------------------------------------------------------------------------------------- the tarball
# What an install runs is followed the way npm and the shell would run it, not matched by file extension:
#   - `npm run build` / `yarn build` / `pnpm run build` in an install script runs that script (and its pre/post scripts)
#   - `node test/setup` runs test/setup.js (node's resolution: X, X.js, X/package.json "main", X/index.js), `node .` the
#     package's main, `node -r ./h` / `--import ./h` load ./h first
#   - `sh setup`, `python3 setup.cfg`, `./configure`: the file named, whatever its extension (or none)
#   - `make` runs the Makefile; `node-gyp rebuild` (also npm's implicit install script when binding.gyp exists and the
#     package has no install / preinstall script) expands the `<!(command)` strings of the .gyp/.gypi files
# Each command and each file it runs is written next to the package as `package.json#<event>...` (behavior/ reads those
# as install-time code, rule_engine by their suffix), so a file in test/ or without a code suffix is still read.

PROJECT_EVENTS = ("preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare")
GYP_SUFFIXES = (".gyp", ".gypi")
MAKEFILES = ("GNUmakefile", "makefile", "Makefile")
COPY_MAX_BYTES = 1024 * 1024        # a file an install script runs, copied in as install-time code
_FOLLOW_DEPTH = 6
_CODE_SUFFIX = {".js": "js", ".mjs": "js", ".cjs": "js", ".sh": "shell", ".bash": "shell", ".py": "python"}
_EXT = {"js": ".js", "shell": ".sh", "python": ".py", "make": ".sh"}
_SHELLS = {"sh", "bash", "dash", "zsh", "ksh"}
_WRAP = {"env", "cross-env", "cross-env-shell", "nohup", "exec", "command", "time", "sudo", "npx", "pnpx", "bunx"}
_NODE_FILE_OPTS = {"-r", "--require", "--import", "--loader", "--experimental-loader"}
_NODE_VALUE_OPTS = _NODE_FILE_OPTS | {"--env-file", "-C", "--conditions", "--input-type", "--title", "--inspect-port",
                                      "--openssl-config", "--icu-data-dir", "--redirect-warnings", "--diagnostic-dir"}
_NPM_RUN = {"run", "run-script", "rum", "urn"}
_NPM_SHORT = {"start": "start", "test": "test", "t": "test", "tst": "test", "restart": "restart", "stop": "stop"}
_GYP_TOOLS = {"node-gyp", "node-gyp-build", "node-pre-gyp", "prebuild"}


def lifecycle_scripts(package_json: Path, events: tuple = LIFECYCLE) -> dict[str, str]:
    """{event: command} of the scripts npm runs when this package is installed."""
    scripts = _scripts_of(_read_json(package_json))
    return {e: str(scripts[e]) for e in events if isinstance(scripts.get(e), str) and scripts[e].strip()}


def _read_json(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(errors="replace"))
    except (OSError, ValueError):
        return {}
    return doc if isinstance(doc, dict) else {}


def _scripts_of(doc: dict) -> dict:
    scripts = doc.get("scripts") if isinstance(doc, dict) else None
    return scripts if isinstance(scripts, dict) else {}


def _split_commands(cmd: str) -> list[list[str]]:
    """A script line as simple commands (&&, ||, ;, |, & and parentheses split; redirections dropped)."""
    import shlex
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars="();<>|&")
        lex.whitespace_split = True
        lex.commenters = ""
        toks = list(lex)
    except ValueError:
        return []
    out: list[list[str]] = [[]]
    skip = False
    for t in toks:
        if skip:
            skip = False
            continue
        if t in ("&&", "||", ";", "|", "&", "(", ")", ";;"):
            out.append([])
        elif set(t) <= set("<>&"):
            skip = True
        else:
            out[-1].append(t)
    return [s for s in out if s]


def _unwrap(toks: list[str]) -> list[str]:
    """Drop `FOO=1`, env / cross-env / npx / `npm exec` ... in front of the command that runs."""
    toks = list(toks)
    for _ in range(8):
        while toks and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]):
            toks.pop(0)
        if not toks:
            break
        head = Path(toks[0]).name
        if head in _WRAP:
            toks.pop(0)
            while toks and toks[0].startswith("-"):
                toks.pop(0)
            continue
        if head in ("npm", "pnpm", "yarn", "bun") and len(toks) > 1 and toks[1] in ("exec", "x", "dlx"):
            toks = toks[2:]
            while toks and toks[0].startswith("-") and toks[0] != "--":
                toks.pop(0)
            if toks and toks[0] == "--":
                toks.pop(0)
            continue
        break
    return toks


def _inside(root: Path, rel: str) -> Path | None:
    """root/rel when it stays inside root (no absolute paths, no `..`), else None."""
    rel = rel.strip()
    if not rel or rel.startswith(("/", "~", "$")) or re.match(r"^[A-Za-z]:", rel) or "\\" in rel:
        return None
    parts = Path(rel).parts
    if ".." in parts:
        return None
    return root / rel


def _rel(root: Path, p: Path) -> str:
    return str(p.relative_to(root)).replace("\\", "/")


def _node_file(root: Path, spec: str) -> Path | None:
    """The file `node <spec>` / `node -r <spec>` loads, by node's resolution of a relative path."""
    base = _inside(root, spec)
    if base is None:
        return None
    for c in (base, *(base.with_name(base.name + s) for s in (".js", ".mjs", ".cjs"))):
        if c.is_file():
            return c
    if base.is_dir():
        main = _read_json(base / "package.json").get("main")
        if isinstance(main, str) and main.strip():
            sub = _inside(base, main)
            if sub is not None:
                for c in (sub, *(sub.with_name(sub.name + s) for s in (".js", ".mjs", ".cjs")), sub / "index.js"):
                    if c.is_file():
                        return c
        for idx in ("index.js", "index.mjs", "index.cjs"):
            if (base / idx).is_file():
                return base / idx
    return None


def _file(root: Path, spec: str) -> Path | None:
    p = _inside(root, spec)
    return p if p is not None and p.is_file() else None


class _Runs:
    """What an install runs: [(tag, command)], [(tag, rel, lang)] files, [(tag, lang, code)] inline code, gyp tags."""

    def __init__(self, root: Path | None, scripts: dict):
        self.root, self.scripts = root, scripts
        self.commands: list[tuple[str, str]] = []
        self.files: list[tuple[str, str, str]] = []
        self.inline: list[tuple[str, str, str]] = []
        self.named: list[str] = []          # path-like operands as written (kept even when the file is not there)
        self.gyp: list[str] = []
        self.gyp_cmds: list[tuple[str, str]] = []   # (.gyp file, command) of node-gyp's command expansions
        self.notes: list[str] = []

    def add_file(self, tag: str, p: Path | None, lang: str, written: str | None = None) -> None:
        if written and not written.startswith("-"):
            self.named.append(re.sub(r"^\./", "", written))
        if p is None or self.root is None:
            return
        item = (tag, _rel(self.root, p), lang)
        if not any(f[1] == item[1] and f[2] == lang for f in self.files):
            self.files.append(item)

    def script(self, tag: str, name: str, depth: int, seen: set) -> None:
        """`npm run <name>`: the script with its pre / post scripts."""
        for n in (f"pre{name}", name, f"post{name}"):
            cmd = self.scripts.get(n)
            if isinstance(cmd, str) and cmd.strip() and n not in seen:
                seen.add(n)
                sub = f"{tag}+{_flat(n)[:40]}"[:100]          # script names are the package's: never a path
                self.commands.append((sub, cmd))
                self.command(sub, cmd, depth + 1, seen)

    def command(self, tag: str, cmd: str, depth: int = 0, seen: set | None = None) -> None:
        seen = set() if seen is None else seen
        if depth > _FOLLOW_DEPTH:
            return
        for toks in _split_commands(cmd):
            self.simple(tag, _unwrap(toks), depth, seen)

    def simple(self, tag: str, toks: list[str], depth: int, seen: set) -> None:
        if not toks:
            return
        root = self.root
        head, args = Path(toks[0]).name, toks[1:]
        if head in ("npm", "pnpm", "yarn", "bun") and args:
            pos = [a for a in args if not a.startswith("-")]
            sub = pos[0] if pos else ""
            if sub in _NPM_RUN and len(pos) > 1:
                self.script(tag, pos[1], depth, seen)
            elif head == "npm" and sub in _NPM_SHORT:
                self.script(tag, _NPM_SHORT[sub], depth, seen)
            elif head in ("yarn", "pnpm") and sub in self.scripts:      # `yarn build` runs the build script
                self.script(tag, sub, depth, seen)
            return
        if head in ("node", "nodejs"):
            i, code = 0, False
            while i < len(args):
                a = args[i]
                if a in ("-e", "--eval", "-p", "--print") and i + 1 < len(args):
                    self.inline.append((tag, "js", args[i + 1]))
                    code = True
                    i += 2
                    continue
                if a.startswith(("--eval=", "--print=")):
                    self.inline.append((tag, "js", a.split("=", 1)[1]))
                    code = True
                elif a in _NODE_FILE_OPTS and i + 1 < len(args):
                    self.add_file(tag, _node_file(root, args[i + 1]) if root else None, "js", args[i + 1])
                    i += 2
                    continue
                elif "=" in a and a.split("=", 1)[0] in _NODE_FILE_OPTS:
                    v = a.split("=", 1)[1]
                    self.add_file(tag, _node_file(root, v) if root else None, "js", v)
                elif a in _NODE_VALUE_OPTS:
                    i += 2
                    continue
                elif a == "--":
                    if not code and i + 1 < len(args):
                        self.add_file(tag, _node_file(root, args[i + 1]) if root else None, "js", args[i + 1])
                    break
                elif not a.startswith("-"):
                    if not code:
                        self.add_file(tag, _node_file(root, a) if root else None, "js", a)
                    break
                i += 1
            return
        if re.fullmatch(r"python[\d.]*|py|pypy3?", head):
            i = 0
            while i < len(args):
                a = args[i]
                if a == "-c" and i + 1 < len(args):
                    self.inline.append((tag, "python", args[i + 1]))
                    return
                if a == "-m" and i + 1 < len(args):
                    mod = args[i + 1].replace(".", "/")
                    if root:
                        self.add_file(tag, _file(root, mod + ".py") or _file(root, mod + "/__main__.py"), "python")
                    return
                if a in ("-W", "-X"):
                    i += 2
                    continue
                if not a.startswith("-"):
                    self.add_file(tag, _file(root, a) if root else None, "python", a)
                    return
                i += 1
            return
        if head in _SHELLS or head in ("source", "."):
            i = 0
            while i < len(args):
                a = args[i]
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:] and i + 1 < len(args):
                    self.command(tag, args[i + 1], depth + 1, seen)
                    return
                if a in ("-o", "+o", "-O", "+O"):
                    i += 2
                    continue
                if not a.startswith(("-", "+")):
                    self.add_file(tag, _file(root, a) if root else None, "shell", a)
                    return
                i += 1
            return
        if head in ("make", "gmake"):
            mfile, mdir, i = None, ".", 0
            while i < len(args):
                a = args[i]
                if a in ("-f", "--file", "--makefile") and i + 1 < len(args):
                    mfile = args[i + 1]
                    i += 2
                    continue
                if a in ("-C", "--directory") and i + 1 < len(args):
                    mdir = args[i + 1]
                    i += 2
                    continue
                if a.startswith(("--file=", "--makefile=", "--directory=")):
                    k, v = a.split("=", 1)
                    if k == "--directory":
                        mdir = v
                    else:
                        mfile = v
                i += 1
            if root:
                d = _inside(root, mdir)
                cands = [mfile] if mfile else list(MAKEFILES)
                found = [d / c for c in cands if d is not None and (d / c).is_file()]
                self.add_file(tag, found[0] if found else None, "make")
            return
        if head in _GYP_TOOLS or (head == "prebuild-install" and "node-gyp" in " ".join(toks)):
            if tag not in self.gyp:
                self.gyp.append(tag)
            return
        if "/" in toks[0] or (root is not None and (root / toks[0]).is_file()):
            p = _file(root, toks[0]) if root else None     # `./configure`, `bin/setup`: the file itself runs
            lang = _CODE_SUFFIX.get(p.suffix.lower(), "shell") if p is not None else "shell"
            self.add_file(tag, p, lang, toks[0])
            return
        for a in args:                                    # any other command: package files it names by code suffix
            if not a.startswith("-") and Path(a).suffix.lower() in _CODE_SUFFIX and "/" not in a[:1]:
                self.add_file(tag, _file(root, a) if root else None, _CODE_SUFFIX[Path(a).suffix.lower()], a)


def install_runs(root: Path | None, doc: dict, events: tuple = LIFECYCLE) -> _Runs:
    """Everything the install scripts of `doc` (a package.json in `root`) run. root None: commands only."""
    scripts = _scripts_of(doc)
    runs = _Runs(root, scripts)
    for e in events:
        cmd = scripts.get(e)
        if isinstance(cmd, str) and cmd.strip():
            runs.commands.append((e, cmd))
            runs.command(e, cmd, 0, {e})
    # npm's default install script: `node-gyp rebuild` when binding.gyp is there and no install / preinstall script is
    if root is not None and "install" in events and (root / "binding.gyp").is_file() \
            and not any(isinstance(scripts.get(e), str) and scripts[e].strip() for e in ("install", "preinstall")):
        runs.gyp.append("install")
    if runs.gyp and root is not None:               # gyp runs the expansions in the .gyp files: follow them like scripts
        tag = runs.gyp[0]
        for p in sorted(root.rglob("*")):
            if p.suffix.lower() in GYP_SUFFIXES and "node_modules" not in p.relative_to(root).parts and p.is_file():
                try:
                    found = gyp_commands(p.read_text(errors="replace")[:4 * 1024 * 1024])
                except OSError:
                    runs.notes.append(f"{_rel(root, p)}: could not be read")
                    continue
                for c in found:
                    runs.gyp_cmds.append((_rel(root, p), c))
                    runs.command(f"{tag}~gyp", c, 1, set())
    return runs


_GYP_CMD = re.compile(r"<!@?(?:pymod_do_main)?\(")


def gyp_commands(text: str) -> list[str]:
    """The `<!(command)` / `<!@(command)` / `<!pymod_do_main(...)` expansions of a .gyp/.gypi file: gyp runs them while
    it generates the build files (balanced parentheses; the string's own escapes are left as they are)."""
    out = []
    for m in _GYP_CMD.finditer(text):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            depth += {"(": 1, ")": -1}.get(text[i], 0)
            i += 1
        body = text[m.end():i - 1] if depth == 0 else text[m.end():m.end() + 2000]
        out.append(("python3 -m " if "pymod_do_main" in m.group(0) else "") + body.replace('\\"', '"'))
    return out


def _make_as_shell(text: str) -> str:
    """A Makefile read as the shell commands it runs: recipe lines without their tab and @/-/+ prefix, $(shell x) as $(x)."""
    lines = []
    for line in text.splitlines():
        if line.startswith("\t"):
            line = line[1:].lstrip("@-+ ")
        lines.append(line.replace("$(shell ", "$("))
    return "\n".join(lines) + "\n"


def _flat(rel: str) -> str:
    return re.sub(r"[^\w.@+-]+", "_", rel.replace("/", "__"))[:100]


def run_texts(root: Path | None, doc: dict, events: tuple = LIFECYCLE, idx: str = "",
              copy_all: bool = True) -> tuple[dict[str, str], list[str]]:
    """({file name: text} of everything the install scripts run, [what could not be read]). Names start with
    `package.json#<event>`: the commands (`.sh`), inline node / python code, the files they run (copied under the
    suffix of the language that runs them; with copy_all False only those whose own suffix is not read as that
    language - the rest are read in place) and the command expansions of the .gyp files node-gyp reads."""
    runs = install_runs(root, doc, events)
    texts: dict[str, str] = {}
    notes: list[str] = []
    for tag, cmd in runs.commands:
        texts[f"package.json#{tag}{idx}.sh"] = cmd + "\n"
    for n, (tag, lang, code) in enumerate(runs.inline):
        name = f"package.json#{tag}{idx}" + (f".{n}" if n else "") + _EXT[lang]
        texts.setdefault(name, code + "\n")
    for tag, rel, lang in runs.files:
        p = root / rel
        if not copy_all and _CODE_SUFFIX.get(p.suffix.lower()) == lang:
            continue
        try:
            if p.stat().st_size > COPY_MAX_BYTES:
                notes.append(f"{rel}: too large to check")
                continue
            text = p.read_text(errors="replace")
        except OSError:
            notes.append(f"{rel}: could not be read")
            continue
        ext = _EXT[lang]
        stem = rel[:-len(ext)] if rel.lower().endswith(ext) else rel
        texts[f"package.json#{tag}{idx}~{_flat(stem)}{ext}"] = _make_as_shell(text) if lang == "make" else text
    notes += runs.notes
    if runs.gyp_cmds:
        texts[f"package.json#{runs.gyp[0]}{idx}~gyp.sh"] = "".join(f"# {rel}\n{c}\n" for rel, c in runs.gyp_cmds)
    return texts, notes


def root_package_jsons(files: list[Path]) -> list[Path]:
    """The package.json files npm may read as the package's own. npm unpacks a tarball without its first path component
    (package/package.json -> package.json), so in an unpacked tarball every package.json exactly one folder below the
    archive root counts (several top folders land in the same place). A shallower decoy beside it used to be taken as
    the root and hid the real install scripts; the shallowest ones are still read too, so nothing is dropped."""
    pkgs = [f for f in files if f.name == "package.json" and f.is_file()]
    if not pkgs:
        return []

    def depth(f):
        idx = [k for k, p in enumerate(f.parts) if p.endswith(".unpacked")]
        return len(f.parts) - 1 - idx[-1] if idx else None

    low = min(len(f.parts) for f in pkgs)
    return [f for f in pkgs if len(f.parts) == low or depth(f) == 2]


def write_lifecycle(files: list[Path], dest: Path, base_name: str, events: tuple = LIFECYCLE) -> list[Path]:
    """What the install scripts of the package root's package.json run (run_texts) as `package.json#<event>...` files
    (read by the rules and behavior/ as install-time code; the evidence then points at the event). Returns the files."""
    roots = [f for f in root_package_jsons(files) if lifecycle_scripts(f, events) or (f.parent / "binding.gyp").is_file()]
    out: list[Path] = []
    for i, pj in enumerate(roots):
        texts, _ = run_texts(pj.parent, _read_json(pj), events, idx=f".{i}" if len(roots) > 1 else "", copy_all=False)
        if not texts:
            continue
        out_dir = dest / f"{base_name}.scripts.unpacked"
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, text in texts.items():
            f = out_dir / name
            f.write_text(text)
            out.append(f)
    return out


def install_time_files(files: list[Path], events: tuple = LIFECYCLE) -> list[str]:
    """Package files the install scripts run (`node install.js`, `sh ./scripts/postinstall.sh`, `node test/setup`, the
    Makefile of `make`, the .gyp files of node-gyp), relative to the package root: code in them runs at install, not
    when the package is used (attack_path.context_of, behavior/)."""
    out = []
    for root_json in root_package_jsons(files):
        root = root_json.parent
        runs = install_runs(root, _read_json(root_json), events)
        out += [rel for _, rel, _ in runs.files]
        out += [n for n in runs.named if Path(n).suffix.lower() in _CODE_SUFFIX and _inside(root, n) is not None]
        if runs.gyp:
            out += [_rel(root, p) for p in sorted(root.rglob("*")) if p.suffix.lower() in GYP_SUFFIXES and p.is_file()]
    return list(dict.fromkeys(out))


def script_named_files(files: list[Path]) -> list[str]:
    """Paths the root package.json's scripts name (as written, without `./`) - kept by extract() whatever their suffix."""
    out = []
    for root_json in root_package_jsons(files):
        doc = _read_json(root_json)
        runs = install_runs(None, doc, tuple(k for k in _scripts_of(doc) if isinstance(k, str)))
        out += [n for n in runs.named if n not in (".", "") and _inside(Path("."), n) is not None]
        main = doc.get("main")
        if isinstance(main, str) and _inside(Path("."), main) is not None:
            out.append(re.sub(r"^\./", "", main))
    return list(dict.fromkeys(out))


def extract(raw: bytes, root: Path, skipped: list) -> list[Path]:
    """Unpack an npm tarball with KEEP_SUFFIXES, then the files its scripts name that those left out (`sh setup`,
    `python3 setup.cfg`, `node test/setup`)."""
    import safe_extract
    safe_extract.extract_targz(raw, root, skipped, KEEP_SUFFIXES)
    named = script_named_files(list(root.rglob("*")))
    extra = tuple(dict.fromkeys(s for n in named for s in ("/" + n.lower().rstrip("/"), "/" + n.lower().rstrip("/") + "/index.js")))
    if extra:
        safe_extract.extract_targz(raw, root, [], extra)
    return list(root.rglob("*"))


def inline_node_code(cmd: str) -> str | None:
    """The code of `node -e CODE` / `node --eval=CODE` / `node -p CODE` in a lifecycle command, else None."""
    import shlex
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    for i, t in enumerate(toks):
        if Path(t).name not in ("node", "nodejs"):
            continue
        for j in range(i + 1, len(toks)):
            a = toks[j]
            if a in ("-e", "--eval", "-p", "--print") and j + 1 < len(toks):
                return toks[j + 1]
            if a.startswith(("--eval=", "--print=")):
                return a.split("=", 1)[1]
            if not a.startswith("-"):
                break
    return None


def fetch(name: str, spec: str | None, dest: Path, meta: dict | None = None, info: dict | None = None) -> tuple[str | None, list[Path]]:
    """(resolved version, unpacked files + lifecycle files). Nothing is run. info gets artifact, scripts, integrity."""
    meta = meta or metadata(name)
    version = pick_version(meta, spec)
    if version is None:
        raise ValueError(f"no version on npm matches '{name}@{spec or 'latest'}'")
    dist = ((meta.get("versions") or {}).get(version) or {}).get("dist") or {}
    url = dist.get("tarball", "")
    if not url.startswith(REGISTRY + "/"):
        raise ValueError("tarball address in the npm metadata is not registry.npmjs.org")
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        raw = resp.read(MAX_TARBALL_BYTES + 1)
    if len(raw) > MAX_TARBALL_BYTES:
        raise ValueError(f"package too large, code not scanned (>{MAX_TARBALL_BYTES >> 20}MB limit)")
    base = f"{name.replace('/', '__')}-{version}"
    root = dest / f"{base}.tgz.unpacked"
    root.mkdir(parents=True, exist_ok=True)
    skipped: list = []
    files = extract(raw, root, skipped)
    life = write_lifecycle(files, dest, base)
    if info is not None:
        info.update(artifact=url.rsplit("/", 1)[-1], artifact_kind="npm", skipped=skipped,
                    scripts={f.name.split("#", 1)[1][:-3]: f.read_text().strip()[:200] for f in life
                             if f.suffix == ".sh" and "~" not in f.name},
                    integrity=dist.get("integrity"))
    return version, files + life


# ------------------------------------------------------------------------------------------ the locked dependency tree

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_MAX = 1000


def malicious_releases(pairs: list[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
    """{(name, version): [MAL- ids]} for the releases OSV's malicious-packages records name. One batch request per
    1,000 releases; only the ids come back, which is enough (MAL- is the malicious-packages database)."""
    import rule_engine
    prefixes = rule_engine.current().malicious_id_prefixes
    pairs = list(dict.fromkeys(pairs))
    out: dict = {}
    for i in range(0, len(pairs), OSV_BATCH_MAX):
        chunk = pairs[i:i + OSV_BATCH_MAX]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]}).encode()
        req = urllib.request.Request(OSV_BATCH_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            results = json.loads(resp.read()).get("results", [])
        for (n, v), r in zip(chunk, results):
            ids = [x.get("id", "") for x in (r or {}).get("vulns", []) if str(x.get("id", "")).startswith(prefixes)]
            if ids:
                out[(n, v)] = ids
    return out


# ------------------------------------------------------------------------- dependencies that run code at install
# npm runs the preinstall / install / postinstall scripts of EVERY package in the tree, not only the ones named in the
# command - the usual way in for npm attacks (ua-parser-js 2021, the 2025 Shai-Hulud worm). Scanning every dependency's
# code would take minutes; scanning the ones that have an install script is what matters for "code runs at install".
# The registry's abbreviated document and package-lock.json both say which versions have one (hasInstallScript).

TREE_MAX_PACKAGES = 1000          # distinct packages per command: 198 popular packages measured at most 537 (nuxt, 4 s)
TREE_WORKERS = 8


def install_script_deps(roots: list[tuple[str, str | None]], deadline: float, skip: set | None = None) -> tuple[list[dict], list[str]]:
    """([{name, version, via}] of packages in the dependency tree of `roots` (name, spec) whose resolved version has an
    install script, [notes]). The tree is resolved like npm does for a fresh install (dependencies + optionalDependencies,
    highest version in range); `skip` = names already scanned. Stops at TREE_MAX_PACKAGES or `deadline` (noted)."""
    import time
    from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
    skip = set(skip or ())
    seen: set = set()                     # (name, range) pairs resolved: one package is asked for with many ranges
    names: set = set()                    # distinct packages - what the limit counts
    found: list[dict] = []
    notes: list[str] = []
    queue = [(n, s, None) for n, s in roots]
    meta_cache: dict = {}

    def resolve(name, spec):
        meta = meta_cache.get(name) or metadata(name)
        meta_cache[name] = meta
        version = pick_version(meta, spec)
        info = ((meta.get("versions") or {}).get(version) or {}) if version else {}
        return version, info

    with ThreadPoolExecutor(TREE_WORKERS) as pool:
        running: dict = {}
        while queue or running:
            while queue and len(running) < TREE_WORKERS * 2:
                name, spec, via = queue.pop(0)
                if (name, spec) in seen or not valid_name(name):
                    continue
                if name not in names and len(names) >= TREE_MAX_PACKAGES:
                    notes.append(f"many dependencies: only the first {TREE_MAX_PACKAGES} distinct packages checked")
                    queue.clear()
                    break
                seen.add((name, spec))
                names.add(name)
                running[pool.submit(resolve, name, spec)] = (name, via)
            if not running:
                break
            left = deadline - time.monotonic()
            if left <= 0:
                notes.append("dependency tree not fully checked within the time limit")
                break
            done, _ = wait(list(running), timeout=left, return_when=FIRST_COMPLETED)
            for fut in done:
                name, via = running.pop(fut)
                try:
                    version, info = fut.result()
                except Exception:
                    continue                      # an unreadable dependency: npm itself would fail on it
                if not version:
                    continue
                if info.get("hasInstallScript") and name not in skip:
                    found.append({"name": name, "version": version, "via": via})
                for key in ("dependencies", "optionalDependencies"):
                    for dep, dspec in (info.get(key) or {}).items() if isinstance(info.get(key), dict) else []:
                        if isinstance(dspec, str) and not dspec.startswith(("file:", "link:", "git", "http", "workspace:")):
                            queue.append((dep, dspec, via or name))
        for fut in running:
            fut.cancel()
    unique = {(f["name"], f["version"]): f for f in found}
    return list(unique.values()), list(dict.fromkeys(notes))


def lock_install_scripts(lock: dict) -> list[dict]:
    """[{name, version, via}] of package-lock.json (v2/v3) entries marked hasInstallScript."""
    out = []
    for path, info in (lock.get("packages") or {}).items():
        if not (path.startswith("node_modules/") and isinstance(info, dict) and info.get("hasInstallScript")
                and info.get("version") and not info.get("link")):
            continue
        parts = path.split("node_modules/")
        name = parts[-1].rstrip("/")
        via = parts[1].rstrip("/") if len(parts) > 2 else None
        out.append({"name": name, "version": str(info["version"]), "via": via})
    return out
