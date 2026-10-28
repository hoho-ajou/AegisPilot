"""
AegisPilot - install command parsing.

Turns a shell command into what the guard has to do about it:
  - packages: PyPI requirements it can scan   [(name, exact_version | None)]
  - unscanned: sources it cannot scan and must tell the human about
               [{"kind", "text", "reason"}]  (VCS/URL, custom index, find-links)
Local paths (`pip install .`, `-e ./pkg`, wheel files) are local code, but what they DEPEND on is fetched from PyPI:
their dependencies are read (project_deps.py) and scanned. Project-level installs that name no package (`uv sync`,
`poetry install`, `pdm install`, `pipenv install`/`sync`, `pip-sync`, `uv pip sync`) are read the same way, with the
lock file's versions. (Ignoring local paths and these commands would let project installs of a CRITICAL version
pass silently.)

Why this exists: the first version matched `pip install <args>` with a regex and
looked at whitespace-separated tokens, so on measured real command shapes it
(a) silently skipped `requests>=2`, `requests[security]` and quoted specs,
(b) treated `-r requirements.txt` and `.` as package names (false REVIEW) and
never looked inside the requirements file, (c) scanned `--index-url <private>`
installs against PyPI. A silent skip is a bypass, so everything it cannot
interpret is either parsed or reported, never dropped.

Tokenizing uses shlex (quotes, `&&`, `;`, `|` splitting); an unparseable
command (unbalanced quotes) yields nothing, i.e. the hook falls through as
before. Fail-open is the guard's existing contract for input it cannot read.
"""
from __future__ import annotations

import re
import shlex
from urllib.parse import urlsplit
from pathlib import Path

import index_config
import npm_parse

# policy knobs: what to do with sources the scanner cannot read.
REVIEW_UNSCANNED_KINDS = {"vcs_or_url", "custom_index", "index_setting", "find_links", "requirements_unreadable", "unparsed", "too_many_packages",
                          "other_ecosystem"}

MAX_REQUIREMENT_FILE_BYTES = 256 * 1024
MAX_REQUIREMENT_DEPTH = 3
MAX_PACKAGES_PER_COMMAND = 200

_PYPI_HOSTS = ("pypi.org", "files.pythonhosted.org")

# options of `pip install` that consume the next token as a value
_VALUE_FLAGS = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root",
    "--python", "--platform", "--abi", "--implementation", "--python-version", "--only-binary",
    "--no-binary", "--progress-bar", "--proxy", "--cert", "--client-cert", "--retries",
    "--timeout", "--trusted-host", "--upgrade-strategy", "--root-user-action", "--src",
    "--config-settings", "-C", "--global-option", "--install-option", "--exists-action",
    "--report", "--cache-dir", "--log", "--keyring-provider", "--index", "--default-index",
}
_OPERATORS = {"&&", "||", ";", "|", "&", ";;", "(", ")", "\n"}
_REDIRECTS = {">", ">>", "<", "<<", ">&", "<&", "&>", "&>>"}

# python -m pip, pip, pip3, pip3.12, uv pip install, uv add, poetry add, pipx install, pipenv install
_PIP_NAME = re.compile(r"^(pip|pip3(\.\d+)?|pip\d(\.\d+)?)$")
_PY_NAME = re.compile(r"^python[\d.]*$")

_REQ = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>[^;@]*)?(?:;.*)?$"
)
_EXACT = re.compile(r"^==\s*([A-Za-z0-9_.+!-]+)\s*$")
_URL = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|git\+|hg\+|svn\+|bzr\+)")


class Parsed:
    def __init__(self) -> None:
        self.packages: list[tuple[str, str | None]] = []
        self.unscanned: list[dict] = []
        self.constraints: dict[str, str] = {}      # normalized name -> exact version pinned by a -c constraints file
        self.dropped = 0                           # packages beyond MAX_PACKAGES_PER_COMMAND (reported, never silently ignored)
        self.lock_pins: dict[str, str] = {}        # normalized name -> version from a lock file (lock-using commands only)
        self.specs: dict[str, str] = {}            # normalized name -> declared range ("" = any), to check a lock pin against
        self.project_installs: list[str] = []      # project directories read for a project-level install
        self.installs = False                      # an install-type command was seen (index settings only matter then)
        self.written: set[str] = set()             # base names of files this same command writes
        self.tools: set[str] = set()               # installers that run (pip, uv, poetry, pdm, pipenv): whose config files matter
        self.command_text = ""                     # the whole command (a script written in it is judged on this text)
        self.local_files: list[tuple[str, str]] = []   # (as written, absolute path) of local wheels / sdists: their code is scanned
        self.ecosystem_packages: list[tuple[str, str, str | None]] = []   # (ecosystem, name, spec) outside PyPI: npm (npm_parse)
        self.npm_lock: list[tuple[str, str]] = []   # every (name, version) in package-lock.json of an npm project install
        self.bundles: list[dict] = []              # files on disk to scan as a bundle {label, kind, paths, texts}: an MCP
                                                   # server script, a plugin, a hook script (scan_engine.scan_bundle)
        self.direct_sources: list[dict] = []       # git / URL installs whose code is fetched and scanned (sources/direct.py)
        self.npm_lock_scripts: list[dict] | None = None   # package-lock.json entries with install scripts (None: no lock read)

    def add_package(self, name: str, version: str | None) -> None:
        item = (name, version)
        if item in self.packages:
            return
        if len(self.packages) < MAX_PACKAGES_PER_COMMAND:
            self.packages.append(item)
        else:
            self.dropped += 1      # a vulnerable package on line 201 of requirements.txt used to pass without a word

    def merge(self, other: "Parsed") -> None:
        """Add what another parse found (an MCP server's launch command inside a plugin, ...)."""
        for name, version in other.packages:
            self.add_package(name, version)
        for u in other.unscanned:
            self.add_unscanned(u["kind"], u["text"], u["reason"], u.get("url"), u.get("origin"))
        for attr in ("ecosystem_packages", "local_files", "bundles", "npm_lock", "project_installs", "direct_sources"):
            mine = getattr(self, attr)
            mine += [x for x in getattr(other, attr) if x not in mine]
        if other.npm_lock_scripts is not None:
            self.npm_lock_scripts = (self.npm_lock_scripts or []) + [d for d in other.npm_lock_scripts
                                                                    if d not in (self.npm_lock_scripts or [])]
        self.installs = self.installs or other.installs
        self.tools |= other.tools
        self.dropped += other.dropped

    def add_unscanned(self, kind: str, text: str, reason: str, url: str | None = None, origin: str | None = None) -> None:
        """url / origin (custom_index): which index, and whether the command chose it ("command") or a config file /
        the session's environment did ("config" / "session_env") - index_trust.py trusts the person's own indexes."""
        if kind in REVIEW_UNSCANNED_KINDS:
            item = {"kind": kind, "text": text[:200], "reason": reason}
            if url:
                item.update(url=url[:300], origin=origin or "command")
            if item not in self.unscanned:
                self.unscanned.append(item)


def _segments(command: str, written: list | None = None) -> list[list[str]]:
    """Split a shell command into simple commands (&&, ||, ;, | ...), dropping redirections.
    written: if given, gets the targets of `>`/`>>` redirections."""
    command = re.sub(r"(?<=\s)\d+(?=[<>])", "", command)   # fd prefix of 2>&1, 2>/dev/null
    # a newline separates commands like `;` (a heredoc writing requirements.txt, then `pip install -r requirements.txt` on
    # the next line used to read as one `cat` command). Quoted newlines stay inside their token.
    lex = shlex.shlex(command, posix=True, punctuation_chars="();<>|&\n")
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    tokens = ["\n" if set(tok) == {"\n"} else tok for tok in lex]
    segs: list[list[str]] = [[]]
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            if written and written[-1][0] == "redirect":
                written[-1] = ("file", tok)
            continue
        if tok in _OPERATORS:
            segs.append([])
        elif tok in _REDIRECTS or re.fullmatch(r"[<>]+&?", tok):
            # `requests>=2.0` unquoted is `requests` plus a redirect to a file named "=2.0":
            # drop the operator and its target, as the shell does.
            skip_next = True
            if ">" in tok and written is not None:
                written.append(("redirect", tok))
        else:
            segs[-1].append(tok)
    return [s for s in segs if s]


# commands that run the rest of the line as another command. `timeout 60 pip install ...` and `env pip install ...` would
# otherwise pass unseen. value: options that take a value.
_WRAPPERS = {
    "sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"}, "command": set(), "time": {"-f", "-o"},
    "nohup": set(), "exec": {"-a"}, "env": {"-u", "-C", "-S", "--unset", "--chdir"}, "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-P", "-u"}, "stdbuf": {"-i", "-o", "-e"}, "chrt": set(), "taskset": set(),
    "timeout": {"-s", "--signal", "-k", "--kill-after"}, "xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"},
}
_NEEDS_OPERAND = {"timeout": 1, "chrt": 1, "taskset": 1}     # `timeout 60 cmd`: the duration comes before the command
# `uv run pip install x`, `poetry run pip install x`: the tool's environment runs pip
_RUNNERS = {("uv", "run"), ("poetry", "run"), ("pdm", "run"), ("pipenv", "run"), ("hatch", "run"), ("rye", "run"),
            ("conda", "run"), ("mamba", "run"), ("micromamba", "run"), ("pixi", "run")}
# index settings given through the environment (`PIP_INDEX_URL=... pip install six` installed six from that index while
# the guard scanned PyPI's six: G6)
_INDEX_ENV = {"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX",
              "PIP_FIND_LINKS", "UV_FIND_LINKS", "PIP_CONFIG_FILE", "UV_CONFIG_FILE", "PIP_PROXY"}


def index_env_findings(assignments: dict, parsed: "Parsed", origin: str = "command") -> None:
    """Report index/config settings that send pip or uv to somewhere other than PyPI. origin: "command" for variables
    set in the command itself, "session_env" for the environment the session started with."""
    for key, value in assignments.items():
        if key not in _INDEX_ENV or not value:
            continue
        if key in ("PIP_FIND_LINKS", "UV_FIND_LINKS"):
            parsed.add_unscanned("find_links", f"{key}={value}", "find-links source set by an environment variable is not scanned")
        elif key in ("PIP_CONFIG_FILE", "UV_CONFIG_FILE", "PIP_PROXY"):
            parsed.add_unscanned("custom_index", f"{key}={value}", "a config file or proxy set by an environment variable can change where packages come from")
        elif not any(h in value for h in _PYPI_HOSTS):
            parsed.add_unscanned("custom_index", f"{key}={value}", "installs from a non-PyPI index set by an environment variable",
                                 url=value, origin=origin)


def _strip_wrappers(seg: list[str], env: dict | None = None) -> list[str]:
    """Drop `FOO=bar`, sudo/env/timeout/nice/... and runner prefixes; the assignments seen are put in env."""
    toks = list(seg)
    for _ in range(10):
        if not toks:
            break
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", toks[0], re.S)
        if m:
            if env is not None:
                env[m.group(1)] = m.group(2)
            toks.pop(0)
            continue
        head = Path(toks[0]).name
        if head in _WRAPPERS:
            toks.pop(0)
            while toks and toks[0].startswith("-") and toks[0] != "--":
                opt = toks.pop(0)
                if opt in _WRAPPERS[head] and toks:
                    toks.pop(0)
            if toks and toks[0] == "--":
                toks.pop(0)
            for _n in range(_NEEDS_OPERAND.get(head, 0)):
                if toks:
                    toks.pop(0)
            continue
        if len(toks) > 1 and (head, toks[1]) in _RUNNERS:
            toks = toks[2:]
            while toks and toks[0].startswith("-"):
                toks.pop(0)                  # runner options (`uv run --with x pip ...` is handled by _install_args)
            continue
        break
    return toks


def _files_written(segments: list[list[str]], redirects: list) -> set[str]:
    """Base names of files a command writes before (or while) it installs: `>`/`>>` targets, tee, cp/mv/install
    destinations, curl -o, wget -O, sed -i. A requirements or project file written in the same command cannot be read in
    advance - the hook runs before the command - so its current contents would be the wrong ones."""
    out = {Path(x[1]).name for x in redirects if x[0] == "file"}
    for seg in segments:
        toks = _strip_wrappers(seg)
        if not toks:
            continue
        head, args = Path(toks[0]).name, toks[1:]
        operands = [a for a in args if not a.startswith("-")]
        if head == "tee":
            out |= {Path(a).name for a in operands}
        elif head in ("cp", "mv", "install", "ln") and len(operands) >= 2:
            out.add(Path(operands[-1]).name)
        elif head in ("curl", "wget"):
            named = False
            for i, a in enumerate(args):
                if a in ("-o", "--output", "--output-document") or (head == "wget" and a == "-O"):
                    if i + 1 < len(args):
                        out.add(Path(args[i + 1]).name)
                        named = True
            # the URL's own file name: `curl -O URL` / `curl -sLO URL` / `curl --remote-name URL`, or wget without -O
            remote = head == "wget" or "--remote-name" in args or "--remote-name-all" in args or \
                any(re.fullmatch(r"-[A-Za-z]*O[A-Za-z]*", a) for a in args)
            if remote and not named:
                out |= {Path(urlsplit(a).path).name for a in operands if re.match(r"^[a-z]+://", a)}
        elif head == "sed" and operands and any(a.startswith("-i") or a == "--in-place" for a in args):
            out.add(Path(operands[-1]).name)
    return {n for n in out if n}


def _install_args(seg: list[str]) -> list[str] | None:
    """If this simple command installs Python packages, return the args after `install`/`add`."""
    if len(seg) > 1 and Path(seg[0]).name == "uv" and seg[1] == "run" and "--with" in seg:
        toks = list(seg)                     # `uv run --with pkg script.py` itself installs pkg
    else:
        toks = _strip_wrappers(seg)
    if not toks:
        return None
    first = Path(toks[0]).name
    rest = toks[1:]
    if _PY_NAME.match(first) and rest[:2] == ["-m", "uv"]:          # python -m uv pip install ...
        first, rest = "uv", rest[2:]
    # `pip download` / `pip wheel` fetch the same files and build their metadata, which runs setup.py of a source
    # distribution: code executes although nothing is "installed". In testing, an agent "checked" an invented
    # name with `pip download` before installing; that command must not pass the guard unseen.
    if _PIP_NAME.match(first) and rest[:1] in (["install"], ["download"], ["wheel"]):
        return rest[1:]
    if _PY_NAME.match(first) and rest[:2] == ["-m", "pip"] and rest[2:3] in (["install"], ["download"], ["wheel"]):
        return rest[3:]
    if first == "uv" and rest[:2] == ["pip", "install"]:
        return rest[2:]
    if first == "uv" and rest[:1] == ["add"]:
        return rest[1:]
    if first == "poetry" and rest[:1] == ["add"]:
        return rest[1:]
    if first in ("pipx", "pipenv") and rest[:1] == ["install"]:
        return rest[1:]
    if first == "pdm" and rest[:1] == ["add"]:
        return rest[1:]
    # download-and-run tools: more dangerous than install, the code executes right away
    if first == "uvx":
        return _first_operand_only(rest)
    if first == "pipx" and rest[:1] == ["run"]:
        return _first_operand_only(rest[1:])
    if first == "uv" and rest[:2] in (["tool", "install"], ["tool", "run"]):
        return _first_operand_only(rest[2:]) if rest[1] == "run" else rest[2:]
    if first == "uv" and rest[:1] == ["run"] and "--with" in rest:
        out = []
        for i, t in enumerate(rest):
            if t == "--with" and i + 1 < len(rest):
                out += [rest[i + 1]]
            elif t.startswith("--with="):
                out += [t.split("=", 1)[1]]
        return out
    return None


# conda-family installs: packages from conda channels, not PyPI - the guard cannot scan them
_CONDA = {"conda", "mamba", "micromamba"}
_CONDA_SUBS = {"install", "create", "update", "upgrade"}
_SETUP_PY_INSTALLS = {"install", "develop", "bdist_wheel", "bdist_egg", "build", "build_ext", "egg_info", "sdist"}


def _other_installs(toks: list[str], parsed: Parsed, cwd: Path | None) -> bool:
    """Install shapes beyond pip/uv/poetry (found by testing 50 command variants): `python setup.py
    install` (runs the project's setup.py), `easy_install pkg`, conda/mamba/micromamba/pixi installs. True if handled."""
    if not toks:
        return False
    first, rest = Path(toks[0]).name, toks[1:]
    if _PY_NAME.match(first) and rest and rest[0].endswith("setup.py") and _SETUP_PY_INSTALLS & set(rest[1:]):
        parsed.installs = True
        _local_source(str(Path(rest[0]).parent) or ".", parsed, cwd)    # its dependencies come from PyPI
        return True
    if first == "easy_install":
        parsed.installs = True
        _parse_install_args(rest, parsed, cwd)
        return True
    sub = rest[0] if rest else ""
    if (first in _CONDA and (sub in _CONDA_SUBS or rest[:2] in (["env", "create"], ["env", "update"]))) \
            or (first == "pixi" and sub in ("add", "install", "global")):
        parsed.installs = True
        parsed.add_unscanned("other_ecosystem", " ".join(toks)[:120],
                             "the guard cannot check packages from conda/pixi channels (only PyPI packages are checked)")
        return True
    return False


_PY_INSTALL_HINT = re.compile(r"\b(pip3?|uv|poetry|pdm|pipx|pipenv|easy_install|conda|mamba)\b")


def _python_inline_code(toks: list[str]) -> str | None:
    """The code of `python -c CODE` (also `-Ic`, `-uc` ...), else None."""
    if not toks or not _PY_NAME.match(Path(toks[0]).name):
        return None
    for i, t in enumerate(toks[1:], 1):
        if t.startswith("-") and not t.startswith("--") and t.endswith("c") and i + 1 < len(toks):
            return toks[i + 1]
        if not t.startswith("-"):
            return None                  # a script path: python runs a file, not inline code
    return None


_PIP_MAIN = re.compile(r"\bpip(?:\._internal(?:\.\w+)*)?\.main\(\s*$")
_PIP_MAIN_IMPORTED = re.compile(r"^\s*from\s+pip(?:\._internal(?:\.\w+)*)?\s+import\s+(?:.*\b)?main\b", re.M)


def _commands_in_python(code: str) -> list[str]:
    """Shell commands written inside Python code: list literals (`subprocess.run(["pip", "install", "x"])`, also with
    sys.executable before `-m pip`, and `pip.main(["install", "x"])`) and plain strings (`os.system("pip install x")`)."""
    out = []
    for m in re.finditer(r"\[([^\[\]]+)\]", code):
        items = [x[1] for x in re.findall(r"(['\"])(.*?)\1", m.group(1))]
        if items:
            cmd = " ".join(shlex.quote(x) for x in items)
            before = code[max(0, m.start() - 40):m.start()]
            if _PIP_MAIN.search(before) or (re.search(r"\bmain\(\s*$", before) and _PIP_MAIN_IMPORTED.search(code)):
                cmd = "pip " + cmd
            out.append(("python " + cmd) if items[0] == "-m" else cmd)
    for m in re.finditer(r"(['\"])((?:(?!\1).)*)\1", code):
        if _PY_INSTALL_HINT.search(m.group(2)) and " " in m.group(2):
            out.append(m.group(2))
    return out


MAX_SCRIPT_BYTES = 512 * 1024
_PY_ARG_OPTS = {"-W", "-X", "--check-hash-based-pycs"}       # python options that take a value


def _python_script(toks: list[str]) -> str | None:
    """The script of `python [opts] script.py args`, else None (-c, -m, a bare `python`)."""
    if not toks or not _PY_NAME.match(Path(toks[0]).name):
        return None
    i = 1
    while i < len(toks):
        t = toks[i]
        if t in _PY_ARG_OPTS:
            i += 2
            continue
        if t.startswith("-"):
            if t == "-" or (not t.startswith("--") and ("c" in t[1:] or "m" in t[1:])):
                return None              # stdin, -c CODE, -m MODULE
            i += 1
            continue
        return t
    return None


_INSTALL_WORD = re.compile(r"\b(install|add|sync)\b")
_RUN_CALLS = {"system", "popen", "run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput",
              "spawnl", "spawnlp", "spawnv", "spawnvp", "execv", "execvp", "execl", "execlp"}
_UNKNOWN = "\x00"                       # a part of the command the script builds at run time (a variable, a call)


def _script_commands(code: str) -> list[str]:
    """Commands a script passes to a process call (`subprocess.run([...])`, `os.system("...")`, `pip.main([...])`):
    only real call sites, read from the AST - text that merely mentions `pip install` (messages, docstrings) is not one.
    A part built at run time becomes _UNKNOWN."""
    import ast
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    pip_main = bool(_PIP_MAIN_IMPORTED.search(code))

    def part(node) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Attribute) and node.attr == "executable":
            return "python"
        if isinstance(node, ast.JoinedStr):
            return "".join(part(v) if not isinstance(v, ast.FormattedValue) else _UNKNOWN for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return part(node.left) + part(node.right)
        return _UNKNOWN

    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""
        is_pip = name == "main" and ((isinstance(f, ast.Attribute) and "pip" in ast.unparse(f.value)) or pip_main)
        if name not in _RUN_CALLS and not is_pip:
            continue
        arg = node.args[-1] if name.startswith(("spawn", "exec")) and len(node.args) > 1 else node.args[0]
        if isinstance(arg, (ast.List, ast.Tuple)):
            items = [part(e) for e in arg.elts]
            if name.startswith(("spawnl", "execl")):
                items = [part(e) for e in node.args[1:]]
            cmd = " ".join(shlex.quote(x) if _UNKNOWN not in x else x for x in items)
        else:
            cmd = part(arg)
        if is_pip:
            cmd = "pip " + cmd
        if _PY_INSTALL_HINT.search(cmd) and _INSTALL_WORD.search(cmd):
            out.append(cmd)
    return out


def _script_installs(script: str, parsed: "Parsed", base: Path | None, depth: int) -> None:
    """`python setup_env.py`: an agent can put `pip install` in a script and run it, so the script (a file on disk, read
    as text, never run) is searched like `python -c` code. Only the script itself; modules it imports are not followed."""
    if Path(script).name in parsed.written:
        # an agent often writes a quick script and runs it in one command: asked only when the command mentions an install
        if parsed.command_text and _PY_INSTALL_HINT.search(parsed.command_text) and _INSTALL_WORD.search(parsed.command_text):
            parsed.add_unscanned("unparsed", script, "runs a Python script made in the same command - what it installs is unknown")
        return
    path = Path(script).expanduser()
    if not path.is_absolute():
        if base is None:
            return
        path = base / path
    try:
        if not path.is_file() or path.stat().st_size > MAX_SCRIPT_BYTES:
            return
        code = path.read_text(errors="replace")
    except OSError:
        return
    if not (_PY_INSTALL_HINT.search(code) and _INSTALL_WORD.search(code)):
        return
    for cmd in _script_commands(code):
        parsed.installs = True
        shown = cmd.replace(_UNKNOWN, "…")
        if _UNKNOWN in cmd:
            parsed.add_unscanned("unparsed", f"{script}: {shown[:60]}",
                                 "install command the script builds at run time (packages from variables, etc.) - what gets installed is unknown")
            continue
        before = (len(parsed.packages), len(parsed.unscanned), len(parsed.project_installs))
        if depth < 3:
            parse_install_command(cmd, base, None, parsed, depth + 1)
        if (len(parsed.packages), len(parsed.unscanned), len(parsed.project_installs)) == before:
            parsed.add_unscanned("unparsed", f"{script}: {shown[:60]}", "could not parse the install command inside the script - what gets installed is unknown")


def _first_operand_only(args: list[str]) -> list[str]:
    """`uvx [opts] pkg[@ver] args...`: only the first non-option token is the package; the rest are its arguments."""
    i = 0
    while i < len(args):
        t = args[i]
        if t == "--from" and i + 1 < len(args):
            return [args[i + 1]]            # the package; the first operand is then just the command to run
        if t.startswith("--from="):
            return [t.split("=", 1)[1]]
        if t in ("--with", "-p", "--python", "--index", "--index-url", "-i", "--extra-index-url"):
            i += 2
            continue
        if t.startswith("-"):
            i += 1
            continue
        return [t]
    return []


def _is_local(path: str, cwd: Path | None) -> bool:
    path = re.sub(r"\[[^\]]*\]$", "", path)       # ".[dev]" / "./pkg[extra]" is still a local path
    if path in (".", ".."):
        return True
    if path.startswith(("./", "../", "/", "~")):
        return True
    if re.search(r"\.(whl|zip|tar\.gz|tgz|tar\.bz2)$", path):
        return True                                # pip reads an archive name as a file path, even a bare `x.whl`
    return bool(cwd and re.search(r"[/\\]", path) and (cwd / path).exists())


def _direct(spec: str, parsed: Parsed) -> None:
    """A git / URL requirement: fetched and scanned when it is an https git repository or archive, else not scanned."""
    from sources import direct
    src = direct.parse_python(spec)
    if src is None:
        parsed.add_unscanned("vcs_or_url", spec, "not an https git repository or package file address, so it cannot be downloaded and checked (ssh, hg, svn, etc.)")
    elif src not in parsed.direct_sources:
        parsed.direct_sources.append(src)


def _requirement(spec: str, parsed: Parsed, cwd: Path | None) -> None:
    spec = spec.strip().strip("'\"")
    if not spec:
        return
    m_at = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)@([^/:\s]+)$", spec)    # pipx/poetry style name@1.2.3
    if m_at:
        ver = m_at.group(2)
        parsed.add_package(m_at.group(1), ver if re.match(r"^\d[\w.!+-]*$", ver) else None)
        return
    if _URL.match(spec) or " @ " in spec or re.match(r"^[A-Za-z0-9._-]+\s*@\s*\S+", spec):
        _direct(spec, parsed)
        return
    if _is_local(spec, cwd):
        _local_source(spec, parsed, cwd)
        return
    m = _REQ.match(spec)
    if not m:
        parsed.add_unscanned("unparsed", spec, "could not parse the requirement (variables, substitution, etc.) - what gets installed is unknown")
        return
    name, rest = m.group("name"), (m.group("spec") or "").strip()
    exact = _EXACT.match(rest)
    parsed.specs.setdefault(_norm(name), rest.strip("() "))
    parsed.add_package(name, exact.group(1) if exact else None)


def _local_source(spec: str, parsed: Parsed, cwd: Path | None) -> None:
    """A local project / wheel / archive: its code is local, its dependencies come from PyPI - read them."""
    import project_deps
    m = re.match(r"^(.*?)(\[([^\]]*)\])?$", spec)
    path_text, extras = m.group(1), {e.strip() for e in (m.group(3) or "").split(",") if e.strip()}
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        if cwd is None:              # never resolve against the guard's own working directory
            parsed.add_unscanned("requirements_unreadable", spec, "working folder unknown, so the local project's dependencies were not checked")
            return
        path = cwd / path
    if path.is_dir():
        _project(path, parsed, cwd, extras=extras, all_groups=False, use_lock=False, shown=spec)
        return
    if path.name in parsed.written:      # `curl -O .../x.whl && pip install x.whl`: the file does not exist yet
        parsed.add_unscanned("requirements_unreadable", spec, "package file downloaded or made in the same command - its code cannot be checked before it runs")
        return
    if not path.is_file():
        return                           # a path that does not exist: pip fails, nothing is installed
    # a local wheel or sdist is a package like one from PyPI: its code is scanned before the install (a README
    # that says "download tool.whl and pip install it" must not pass with only its dependency list read)
    if (spec, str(path)) not in parsed.local_files:
        parsed.local_files.append((spec, str(path)))
    if path.suffix == ".whl":
        reqs, bad = project_deps.wheel_requires(path)
        for r in reqs:
            _requirement(r, parsed, cwd)
        for why in bad:
            parsed.add_unscanned("requirements_unreadable", spec, why)
    else:
        parsed.add_unscanned("requirements_unreadable", spec, "dependencies of a local source archive are unknown until it is installed (built)")


def _project(path: Path, parsed: Parsed, cwd: Path | None, extras=None, all_groups=False, use_lock=True,
             shown: str = ".", pipenv=False) -> None:
    import project_deps
    parsed.project_installs.append(str(path))
    touched = parsed.written & {"pyproject.toml", "Pipfile", "Pipfile.lock", "setup.cfg", "setup.py", "uv.lock", "poetry.lock", "pdm.lock"}
    if touched:
        parsed.add_unscanned("requirements_unreadable", shown, f"the same command writes project files ({', '.join(sorted(touched))}) - their contents are unknown before it runs")
    reqs, bad = project_deps.manifest(path, extras=extras, all_groups=all_groups)
    if pipenv and not (path / "Pipfile").is_file():
        reqs += project_deps.pipfile_lock_direct(path)
    if use_lock:
        pins, bad_lock = project_deps.lock_pins(path)
        parsed.lock_pins.update({k: v for k, v in pins.items() if k not in parsed.lock_pins})
        bad += bad_lock
    for why in bad:
        parsed.add_unscanned("requirements_unreadable", f"{shown} ({path.name or '.'})", why)
    if not reqs and not bad and not any((path / f).is_file() for f in ("pyproject.toml", "Pipfile", "setup.cfg", "Pipfile.lock")):
        parsed.add_unscanned("requirements_unreadable", shown, "no project dependency file found (pyproject.toml, Pipfile, etc.)")
    for r in reqs:
        _requirement(r, parsed, cwd)


# project-level install commands that name no package: (tool, subcommand) -> uses the lock file
_PROJECT_COMMANDS = {("uv", "sync"), ("poetry", "install"), ("poetry", "sync"), ("poetry", "update"), ("pdm", "install"),
                     ("pdm", "sync"), ("pdm", "update"), ("pipenv", "sync"), ("pipenv", "update")}


def _project_command(seg: list[str], parsed: Parsed, cwd: Path | None) -> bool:
    """uv sync / poetry install / pdm install / pipenv install (no package) / pipenv sync / pip-sync / uv pip sync."""
    toks = list(seg)
    while toks and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[0]) or toks[0] in ("sudo", "command", "time", "nohup", "exec")):
        toks.pop(0)
    if not toks:
        return False
    first, rest = Path(toks[0]).name, toks[1:]
    # requirements-file sync: pip-sync [files], uv pip sync <files>
    files = None
    if first == "pip-sync":
        files = [t for t in rest if not t.startswith("-")] or ["requirements.txt"]
    elif first == "uv" and rest[:2] == ["pip", "sync"]:
        files = [t for t in rest[2:] if not t.startswith("-")]
    if files is not None:
        if cwd is None:
            parsed.add_unscanned("requirements_unreadable", " ".join(seg)[:80], "working folder unknown, so the requirements file was not checked")
            return True
        for f in files:
            if cwd is not None:
                if f.endswith(".toml"):
                    _project(cwd / Path(f).parent, parsed, cwd, all_groups=True, use_lock=True, shown=f)
                else:
                    _read_requirements(cwd / f, parsed, cwd, 1, f)
        return True
    sub = rest[0] if rest else ""
    is_pipenv_install = first == "pipenv" and sub == "install" and not [t for t in rest[1:] if not t.startswith("-")]
    if (first, sub) not in _PROJECT_COMMANDS and not is_pipenv_install:
        return False
    target = cwd
    for i, t in enumerate(rest):                       # uv --directory/--project, poetry/pdm -C/--directory/--project
        if t in ("--directory", "--project", "-C", "-p") and i + 1 < len(rest):
            target = (cwd / rest[i + 1]) if cwd is not None else Path(rest[i + 1])
        elif t.startswith(("--directory=", "--project=")):
            target = (cwd / t.split("=", 1)[1]) if cwd is not None else Path(t.split("=", 1)[1])
    if target is None:               # never a silent pass: the folder is unknown, so is what gets installed
        parsed.add_unscanned("requirements_unreadable", " ".join(seg)[:80], "working folder unknown, so the project dependencies were not checked")
    else:
        _project(target, parsed, cwd, all_groups=True, use_lock=True, shown=" ".join(seg)[:80], pipenv=first == "pipenv")
    return True


def _vtuple(v: str):
    m = re.match(r"^\s*v?(\d+(?:\.\d+)*)", v)
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def satisfies(version: str, spec: str) -> bool:
    """Does `version` meet a PEP 440 range like ">=5.4,<7"? Unknown forms -> True (the lock pin is kept: a false BLOCK
    shows, a skipped scan would not)."""
    spec = (spec or "").strip()
    if not spec or spec == "*":
        return True
    try:
        from packaging.specifiers import SpecifierSet
        from packaging.version import Version
        return Version(version) in SpecifierSet(spec)
    except ImportError:
        pass
    except Exception:
        return True
    have = _vtuple(version)
    if have is None:
        return True
    for clause in spec.split(","):
        m = re.match(r"^\s*(==|!=|>=|<=|~=|>|<)\s*([\w.*+!-]+)\s*$", clause)
        if not m:
            return True
        op, want_s = m.groups()
        want = _vtuple(want_s)
        if want is None or "*" in want_s:
            return True
        n = max(len(have), len(want))
        a, b = have + (0,) * (n - len(have)), want + (0,) * (n - len(want))
        ok = {"==": a == b, "!=": a != b, ">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b,
              "~=": a >= b and a[:len(want) - 1] == b[:len(want) - 1]}[op]
        if not ok:
            return False
    return True


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _read_constraints(path: Path, parsed: Parsed, depth: int, shown: str) -> None:
    """A constraints file (-c) installs nothing, but pip then installs the pinned version of every listed package that
    something else asks for. Without reading it, an unpinned `pyyaml` in requirements.txt is scanned as the latest release
    while pip installs the constrained (possibly vulnerable) one. Only exact `name==version` pins are applied."""
    if depth > MAX_REQUIREMENT_DEPTH:
        parsed.add_unscanned("requirements_unreadable", shown, "constraints nested too deep")
        return
    try:
        if path.stat().st_size > MAX_REQUIREMENT_FILE_BYTES:
            parsed.add_unscanned("requirements_unreadable", shown, "constraints file too large")
            return
        text = path.read_text(errors="ignore")
    except OSError:
        return
    text = re.sub(r"\\\n", "", text)
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-c ", "--constraint ")) or line.startswith("--constraint="):
            nested = re.split(r"[ =]", line, maxsplit=1)[1].strip()
            _read_constraints(path.parent / nested, parsed, depth + 1, nested)
            continue
        if line.startswith("-") or _URL.match(line):
            continue
        m = _REQ.match(line)
        if not m:
            continue
        pin = _EXACT.match((m.group("spec") or "").strip())
        if pin:
            parsed.constraints.setdefault(_norm(m.group("name")), pin.group(1))


def _read_requirements(path: Path, parsed: Parsed, cwd: Path | None, depth: int, shown: str) -> None:
    if path.name in parsed.written:
        parsed.add_unscanned("requirements_unreadable", shown, "requirements file written in the same command - its contents are unknown before it runs")
        return
    if depth > MAX_REQUIREMENT_DEPTH:
        parsed.add_unscanned("requirements_unreadable", shown, "requirements nested too deep")
        return
    try:
        if path.stat().st_size > MAX_REQUIREMENT_FILE_BYTES:
            parsed.add_unscanned("requirements_unreadable", shown, "requirements file too large")
            return
        text = path.read_text(errors="ignore")
    except OSError:
        # Not there yet. Usually the same command writes it first (`cat > r.txt <<EOF ... && pip install -r r.txt`), which
        # the hook sees before anything runs, so the contents cannot be known. Used to pass silently (G4); a path that
        # really does not exist only costs a question.
        parsed.add_unscanned("requirements_unreadable", shown, "cannot read the requirements file (missing, or made in the same command) - what gets installed is unknown")
        return
    text = re.sub(r"\\\n", "", text)
    for raw in text.splitlines():
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")) or line.startswith(("-r=", "--requirement=")):
            if line.split()[0] in ("-c", "--constraint"):
                nested = re.split(r"[ =]", line, maxsplit=1)[1].strip()
                _read_constraints(path.parent / nested, parsed, 1, nested)   # installs nothing, but fixes versions
                continue
            nested = re.split(r"[ =]", line, maxsplit=1)[1].strip()
            _read_requirements((path.parent / nested), parsed, cwd, depth + 1, nested)
            continue
        if line.startswith(("-i ", "--index-url", "--extra-index-url")):
            url = re.split(r"[ =]", line, maxsplit=1)[1].strip() if re.search(r"[ =]", line) else line
            if not any(h in url for h in _PYPI_HOSTS):
                parsed.add_unscanned("custom_index", f"{shown}: {line}", "non-PyPI index", url=url)
            continue
        if line.startswith(("-f ", "--find-links")):
            parsed.add_unscanned("find_links", f"{shown}: {line}", "find-links sources are not scanned")
            continue
        if line.startswith("-e ") or line.startswith("--editable"):
            target = (line.split(None, 1)[1] if " " in line else "").strip()
            if _URL.match(target):
                _requirement(target, parsed, cwd)
            elif target:
                _local_source(target, parsed, path.parent)      # `-e .` in a requirements file: relative to that file
            continue
        if line.startswith("-"):
            continue  # --hash, --no-binary, ... options of the file
        line = re.sub(r"\s+--hash=\S+", "", line)
        _requirement(line, parsed, cwd)


def _merge_direct_references(args: list[str]) -> list[str]:
    """`pkg @ https://...` arrives as three tokens; make it one requirement string."""
    out: list[str] = []
    i = 0
    while i < len(args):
        if args[i] == "@" and out and i + 1 < len(args):
            out[-1] = f"{out[-1]} @ {args[i + 1]}"
            i += 2
            continue
        out.append(args[i])
        i += 1
    return out


def _parse_install_args(args: list[str], parsed: Parsed, cwd: Path | None) -> None:
    args = _merge_direct_references(args)
    i = 0
    while i < len(args):
        tok = args[i]
        flag, eq, inline = tok.partition("=") if tok.startswith("--") else (tok, "", "")
        if tok.startswith("-") and not tok.startswith("--") and len(tok) > 2 and tok[:2] in _VALUE_FLAGS:
            flag, inline = tok[:2], tok[2:]          # -rrequirements.txt, -ihttps://...
            eq = "x"
        if flag in _VALUE_FLAGS:
            if eq:
                value = inline
                i += 1
            else:
                value = args[i + 1] if i + 1 < len(args) else ""
                i += 2
            if flag in ("-r", "--requirement"):
                if cwd is not None:
                    if Path(value).name in ("pyproject.toml", "setup.cfg", "setup.py"):      # `uv pip install -r pyproject.toml`
                        _project((cwd / value).parent, parsed, cwd, use_lock=False, shown=value)
                    else:
                        _read_requirements((cwd / value), parsed, cwd, 1, value)
            elif flag in ("-c", "--constraint"):
                if cwd is not None:
                    _read_constraints((cwd / value), parsed, 1, value)
            elif flag in ("-e", "--editable"):
                if _URL.match(value):
                    _direct(value, parsed)
                elif value:
                    _local_source(value, parsed, cwd)
            elif flag in ("-i", "--index-url", "--extra-index-url", "--index", "--default-index"):
                if not any(h in value for h in _PYPI_HOSTS):
                    parsed.add_unscanned("custom_index", value, "installs from a non-PyPI index", url=value)
            elif flag in ("-f", "--find-links"):
                parsed.add_unscanned("find_links", value, "find-links sources are not scanned")
            continue
        if tok.startswith("-"):
            i += 1
            continue
        _requirement(tok, parsed, cwd)
        i += 1


_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}


def _inner_command(seg: list[str]) -> str | None:
    """`bash -c "..."`, `sh -lc '...'`, `eval ...`: the command string run inside (G3)."""
    toks = _strip_wrappers(seg)
    if not toks:
        return None
    head = Path(toks[0]).name
    if head == "eval":
        return " ".join(toks[1:])
    if head in _SHELLS:
        for i, t in enumerate(toks[1:], 1):
            if t.startswith("-") and not t.startswith("--") and "c" in t[1:] and i + 1 < len(toks):
                return toks[i + 1]
    return None


_TOOL_OF = {"uv": "uv", "uvx": "uv", "poetry": "poetry", "pdm": "pdm", "pipenv": "pipenv", "pipx": "pip", "pip-sync": "pip"}


def _tool_families(seg: list[str]) -> set[str]:
    """Installers named in a simple command (`poetry run pip install` names both)."""
    out = set()
    for i, t in enumerate(seg):
        n = Path(t).name
        if n in _TOOL_OF:
            out.add(_TOOL_OF[n])
        elif _PIP_NAME.match(n) or (n == "pip" and i and seg[i - 1] == "-m"):
            out.add("pip")
    return out


_CONFIG_FILES = {"pip.conf", "pip.ini", "uv.toml", ".npmrc"}


def _expand_head(seg: list[str], aliases: dict, variables: dict, parsed: Parsed) -> list[str] | None:
    """`alias p=pip; p install x`, `P=pip; $P install x`: put the real command back in the command position. A variable
    that cannot be resolved in front of an install-looking command is reported, never dropped."""
    stripped = _strip_wrappers(seg)
    if not stripped:
        return seg
    prefix, head = seg[:len(seg) - len(stripped)], stripped[0]
    if head in aliases:
        try:
            return prefix + shlex.split(aliases[head]) + stripped[1:]
        except ValueError:
            return seg
    m = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", head)
    if m:
        if m.group(1) in variables:
            try:
                return prefix + shlex.split(variables[m.group(1)]) + stripped[1:]
            except ValueError:
                return seg
        if any(t in ("install", "add", "sync") for t in stripped[1:]):
            parsed.installs = True
            parsed.add_unscanned("unparsed", " ".join(seg)[:80], "command built from variables - what it runs is unknown in advance")
            return None
    return seg


def parse_install_command(command: str, cwd: str | Path | None = None, env: dict | None = None,
                          _parsed: Parsed | None = None, _depth: int = 0) -> Parsed:
    """env: the environment the command will run in (the hook's own), for index settings such as PIP_INDEX_URL."""
    parsed = _parsed if _parsed is not None else Parsed()
    base = Path(cwd) if cwd else None
    try:
        redirects: list = []
        segments = _segments(command, redirects)
    except ValueError:
        return parsed       # unbalanced quotes etc.: not something we can read -> fall through
    parsed.written |= _files_written(segments, redirects)
    if not _depth:
        parsed.command_text = command
    exported: dict = {}
    shell_vars: dict = {}
    aliases: dict = {}
    for seg in segments:
        if seg[0] == "alias":
            for tok in seg[1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    aliases[k] = v
            continue
        if all(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t) for t in seg):      # `P=pip` on its own: a shell variable
            shell_vars.update(t.split("=", 1) for t in seg)
            continue
        seg = _expand_head(seg, aliases, {**shell_vars, **exported}, parsed)
        if seg is None:
            continue
        if seg[0] == "export":
            for tok in seg[1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    exported[k] = v
            continue
        inner = _inner_command(seg)
        if inner is not None:
            if _depth < 3:
                parse_install_command(inner, base, None, parsed, _depth + 1)
            elif re.search(r"\b(pip|uv|poetry|pdm|pipenv|pipx|uvx)\b", inner):
                parsed.add_unscanned("unparsed", inner[:80], "shell nested in shell too deep to parse")
            continue
        # `cd sub && uv sync`: project files and -r paths are relative to where the install runs. Only a literal path is
        # followed; `cd -`, `cd $X`, `cd ~user` leave the folder unknown for the rest of the command.
        if seg and seg[0] == "cd":
            target = seg[1] if len(seg) > 1 else "~"
            if base is not None and re.fullmatch(r"[\w./~-]+", target) and target != "-":
                base = (base / Path(target).expanduser()).resolve() if not target.startswith("/") else Path(target)
            else:
                base = None
            continue
        why = index_config.config_command(_strip_wrappers(seg))
        if why:                                  # index_setting: a change of where installs come from, not an install
            parsed.add_unscanned("index_setting", " ".join(seg)[:120], why)
            continue
        if _project_command(seg, parsed, base):
            parsed.tools |= _tool_families(seg)
            continue
        code = _python_inline_code(_strip_wrappers(seg))
        if code is not None:
            if _PY_INSTALL_HINT.search(code) and re.search(r"\b(install|add|sync|create)\b", code):
                before = (len(parsed.packages), len(parsed.unscanned), len(parsed.project_installs))
                for inner_cmd in _commands_in_python(code):
                    if _depth < 3:
                        parse_install_command(inner_cmd, base, None, parsed, _depth + 1)
                if (len(parsed.packages), len(parsed.unscanned), len(parsed.project_installs)) == before:
                    parsed.add_unscanned("unparsed", code[:80], "could not parse the install command inside Python code - what gets installed is unknown")
                parsed.installs = True
            continue
        if _other_installs(_strip_wrappers(seg), parsed, base):
            continue
        if npm_parse.handle(_strip_wrappers(seg), parsed, base, Path((env or {}).get("HOME") or Path.home())):
            continue
        script = _python_script(_strip_wrappers(seg))
        if script is not None:
            _script_installs(script, parsed, base, _depth)
            continue
        args = _install_args(seg)
        if args is not None:
            parsed.installs = True
            parsed.tools |= _tool_families(seg)
            assigned: dict = dict(exported)
            stripped = _strip_wrappers(seg, assigned)
            index_env_findings(assigned, parsed)
            if any(Path(x).name == "xargs" for x in seg[:len(seg) - len(stripped)]):
                parsed.add_unscanned("unparsed", " ".join(seg)[:80], "install targets passed through xargs are unknown before it runs")
            _parse_install_args(args, parsed, base)
    if _depth:
        return parsed
    if env and (parsed.installs or parsed.project_installs):
        index_env_findings(env, parsed, "session_env")   # set before the session started (the hook runs in the same environment)
    written_config = parsed.written & _CONFIG_FILES
    if written_config:
        parsed.add_unscanned("index_setting", ", ".join(sorted(written_config)),
                             "the same command writes a package config file - later installs may download from elsewhere")
    if parsed.tools and (parsed.installs or parsed.project_installs):    # index-url & co. in the tools' own config files
        try:
            from index_trust import urls_in
            for kind, text, reason in index_config.findings(parsed.tools, base, env):
                found = urls_in(text)
                parsed.add_unscanned(kind, text, reason, url=found[0] if found else None, origin="config")
        except Exception as e:                   # a config we cannot read must not become a silent pass
            parsed.add_unscanned("custom_index", "package index config", f"could not check the package config file: {type(e).__name__}")
    if parsed.dropped:
        parsed.add_unscanned("too_many_packages", f"only {len(parsed.packages)} of {len(parsed.packages) + parsed.dropped} checked",
                             f"more than {MAX_PACKAGES_PER_COMMAND} packages in one command: {parsed.dropped} not checked")
    if parsed.lock_pins:          # lock-using tools install the locked version of a dependency declared as a range...
        # ...unless the lock no longer satisfies the range (the manifest was edited, e.g. after a guard card): the tool then
        # re-resolves, so the stale pin would be a false BLOCK that loops (e.g. pyyaml>=5.4 + uv.lock 5.3.1)
        parsed.packages = [(n, parsed.lock_pins[_norm(n)])
                           if v is None and _norm(n) in parsed.lock_pins and satisfies(parsed.lock_pins[_norm(n)], parsed.specs.get(_norm(n), ""))
                           else (n, v) for n, v in parsed.packages]
    if parsed.constraints:        # pip installs the constrained version for packages that were listed without one
        parsed.packages = [(n, v) if v is not None or _norm(n) not in parsed.constraints else (n, parsed.constraints[_norm(n)])
                           for n, v in parsed.packages]
    return parsed
