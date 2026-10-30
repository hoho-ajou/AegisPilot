"""
AegisPilot - shared protected-path logic (self-tampering guard).

Scope: agent tool calls (shell commands, file edits) that touch the files the guard itself depends
on to run correctly - not just the agent's settings, but the whole hook/scan_engine footprint, since the hook's own
fail-open design means breaking any of these has the same effect as disabling it outright.

Tool-independent: the guard's own paths are listed here; the agent's own config files (where its hooks are registered)
come from the adapter (adapters/<agent>.CONFIG_FRAGMENTS, MCP_CONFIG_NAMES). `agent=None` means the default adapter.
"""
from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path

# fragments matched against a raw path string (shell command text or a file edit's path) - deliberately broad substring
# matches, not exact paths, since both can appear relative, absolute, or ~-expanded.
GUARD_DIR = Path(__file__).resolve().parent
GUARD_FRAGMENTS = [
    "aegis-pilot/",
    ".aegis/",   # last_review.json and reports/ are what the user is told to trust (agent-writable otherwise)
    str(GUARD_DIR) + "/",   # where this copy really is (a plugin lives in the agent's plugin cache)
]


def guard_own_fragments() -> list[str]:
    """The guard's own paths, plus where each agent keeps installed plugins (adapters' PLUGIN_FRAGMENTS): removing that
    folder removes the guard with the other plugins."""
    from adapters import all_adapters
    frags = list(GUARD_FRAGMENTS)
    for a in all_adapters():
        frags += [f for f in getattr(a, "PLUGIN_FRAGMENTS", ()) if f not in frags]
    return frags


def _fragment_in(frag: str, text: str) -> bool:
    """`frag` in a shell command. A folder fragment ("x/") also matches the folder named without the slash
    (`rm -rf .aegis`, `mv <guard dir> /tmp`), but not a longer name that starts the same (`.aegisx`)."""
    if frag in text:
        return True
    if frag.endswith("/"):
        return re.search(re.escape(frag[:-1]) + r"(?=$|[\s'\";&|)<>])", text) is not None
    return False


def _plugin_names() -> tuple[set, set]:
    """(plugin names, marketplace names) this guard is installed under: its own plugin.json, the marketplace folder of
    the plugin cache it sits in (~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/), plus the default names
    (the plugin and marketplace since 2026-10-25, and the folder name of a manual install)."""
    import json
    plugins, markets = {"aegis-pilot"}, {"hoho-ajou"}
    if len(GUARD_DIR.parents) > 3 and GUARD_DIR.parents[2].name == "cache" and GUARD_DIR.parents[3].name == "plugins":
        markets.add(GUARD_DIR.parents[1].name)
    try:
        plugins.add(json.loads((GUARD_DIR / ".claude-plugin" / "plugin.json").read_text()).get("name"))
    except (OSError, ValueError, AttributeError):
        pass
    ok = lambda v: isinstance(v, str) and re.fullmatch(r"[\w.-]{1,128}", v)
    return {v for v in plugins if ok(v)}, {v for v in markets if ok(v)}


def command_disables_guard(command: str) -> bool:
    """`claude plugin disable|uninstall <the guard>` or removing its marketplace (which uninstalls it): through the
    agent's shell this switches the guard off like editing its hook settings does (2026-10-24, plugin distribution)."""
    if not re.search(r"\bclaude\b[^\n;&|]*\bplugins?\b", command):
        return False
    plugins, markets = _plugin_names()
    for seg in re.split(r"[;&|\n]+", command):
        if not re.search(r"\bclaude\b.*\bplugins?\b", seg):
            continue
        words = re.findall(r"[\w.@/-]+", seg)
        names = {w.split("@", 1)[0] for w in words} | {w.split("@", 1)[1] for w in words if "@" in w}
        if re.search(r"\bplugins?\s+(disable|uninstall|remove|rm)\b", seg) and names & plugins:
            return True
        if re.search(r"\bmarketplace\s+(remove|rm)\b", seg) and names & (markets | plugins):
            return True
    return False


_GUARD_CLI_CHANGES = re.compile(r"guard_cli\.py\W+(installs|repair|system-install|system-uninstall|ml-install|ml-uninstall)\b")


def command_changes_guard_install(command: str) -> bool:
    """`guard_cli.py installs|repair|system-install|system-uninstall|ml-install|ml-uninstall` run by the agent: each can
    turn a guard off or replace what it runs, so it is the person's call even though the guard's own CLI does the work."""
    return bool(_GUARD_CLI_CHANGES.search(command))


def path_is_guard_own(path_text: str) -> bool:
    """The guard itself - its files, its records and its settings (.aegis/, ~/.aegis/) - as opposed to the agent's own
    settings, which are protected too but may be changed for other reasons."""
    p = _path_text(path_text)
    return any(frag in path_text or frag.lower() in p for frag in guard_own_fragments())


_GUARD_HOOK_MARKERS = ("pretooluse_check.py", "pretooluse_editwrite_check.py", "codex_pretooluse.py")


def settings_change_disables_guard(file_path: str, proposed_text: str | None) -> bool:
    """An edit of an agent settings file that turns the guard off: one of its hook commands disappears, the guard
    plugin is switched off (enabledPlugins), every hook is disabled (disableAllHooks), or a JSON settings file stops
    parsing (the agent would drop the whole file, hooks included). An edit whose result is unknown counts as one."""
    import json
    if proposed_text is None:
        return True
    try:
        before = Path(file_path).expanduser().read_text(encoding="utf-8", errors="replace")
    except OSError:
        before = ""
    count = lambda t: sum(t.count(m) for m in _GUARD_HOOK_MARKERS)  # noqa: E731
    if count(proposed_text) < count(before):
        return True
    def load(t):
        try:
            v = json.loads(t)
            return v if isinstance(v, dict) else None
        except ValueError:
            return None
    after, was = load(proposed_text), load(before) or {}
    if after is None:
        return file_path.endswith(".json") and bool(before.strip()) and load(before) is not None
    if after.get("disableAllHooks") is True and was.get("disableAllHooks") is not True:
        return True
    plugins, _ = _plugin_names()
    switched_off = {k for k, v in (after.get("enabledPlugins") or {}).items() if v is False}
    already_off = {k for k, v in (was.get("enabledPlugins") or {}).items() if v is False}
    return any(k.split("@", 1)[0] in plugins for k in switched_off - already_off)


def _agent(agent):
    if agent is None:
        from adapters import DEFAULT
        return DEFAULT
    return agent


def protected_fragments(agent=None) -> list[str]:
    """The guard's own paths + the agent's settings/hooks paths.
    MCP config files are deliberately NOT in this list: they have their own, more specific MCP check
    (mcp_guard.check_new_mcp_servers) that distinguishes known from unknown servers, which a generic "protected path"
    flag would shadow - found via testing this exact collision (.mcp.json matched here first and the MCP-specific
    message never fired)."""
    from adapters import all_adapters
    frags = list(_agent(agent).CONFIG_FRAGMENTS)
    for a in all_adapters():                       # every agent's settings, not only the running one's (2026-10-23)
        frags += [f for f in a.CONFIG_FRAGMENTS if f not in frags]
    return frags + [f for f in guard_own_fragments() if f not in frags]


def shell_protected_fragments(agent=None) -> list[str]:
    """Shell-only: MCP config tampering via shell (sed/etc, not a file edit) has no diffing available, so it still falls
    under the generic self-protection catch-all there."""
    return protected_fragments(agent) + list(_agent(agent).MCP_CONFIG_NAMES)


# command tokens that indicate the Bash command WRITES to whatever path it
# names, as opposed to just reading it (cat/grep/ls on a protected path is
# not a tampering attempt). Deliberately conservative: a write-looking token
# anywhere in the command is enough to flag, since under-flagging here is the
# expensive mistake (the whole point is "catch it before the safety net is
# gone").
# a word in command position (the start, after ; & | ( or `, or after sudo / xargs / env ...), not an argument:
# `pip install x` and `pip install patch` are not the `install` / `patch` tools
_CMD = r"(?:^|[;&|(`]\s*|\b(?:sudo|xargs|env|exec|command|nohup|time|busybox)\s+(?:-\S+\s+)*)"
_WRITE_INDICATOR = re.compile(
    r"\bsed\s+-i\b|\bmv\b|\brm\b|\bcp\b|\btruncate\b|\btee\b|\bchmod\b|>>?|\bdd\b"
    # more tools that write, link or delete (an audit wrote the policy file with each of these unflagged, 2026-10-30)
    + r"|" + _CMD + r"(?:ln|install|rsync|touch|unlink|rmdir|shred|chown|patch|zip|unzip|tar|sponge)\b"
    + r"|" + _CMD + r"(?:perl\b[^|;&\n]*\s-[a-zA-Z]*i|awk\b[^|;&\n]*-i\s*inplace"
    + r"|git\s+(?:checkout|restore|reset|clean|apply|am|mv|rm|stash|switch|merge|pull|cherry-pick|revert)\b"
    + r"|(?:curl|wget)\b[^|;&\n]*\s-[a-zA-Z]*[oO]\b)"
    + r"|-delete\b",
    re.M,
)
# a one-line program (python3 -c, node -e, php -r, ...) naming a protected path, with anything in it that writes, links
# or deletes
_INLINE_PROGRAM = re.compile(r"\b(?:python[\d.]*|node|nodejs|deno|bun|ruby|perl|php)\b[^|;&\n]*\s-[a-zA-Z]*[ceE]\b"
                             r"|\bphp\b[^|;&\n]*\s-r\b")
_INLINE_WRITES = re.compile(r"""['"][wax]b?\+?['"]|\bwrite|\bunlink|\bremove|\brename|\breplace|rmtree|symlink|\bcopy|"""
                            r"""\bmove|chmod|truncate|\bsystem\b|subprocess|child_process|\bexec|\bspawn|put_contents|"""
                            r"""fwrite|rmdir""")
# a shell pattern standing for a protected dot-folder (`.ae*`, `.cl?ude`): the name never appears, the shell expands it
_GLOB_TOKEN = re.compile(r"""[^\s'"=;&|<>()]*[*?\[][^\s'"=;&|<>()]*""")


# `2>&1`, `>&2` and `> /dev/null` only route output streams; they write no file, yet the `>` in them used to make every
# command that merely READ a protected file (`cat .claude/settings.json; pip install ... 2>&1 | tail`) look like tampering
# (found in a real agent run). Only a redirect to an actual path still counts: `> .claude/settings.json`, `>& file`, `&> file`.
_HARMLESS_REDIRECT = re.compile(r"\d*>&\d+|\d*>>?\s*/dev/null|&>>?\s*/dev/null")


def command_touches_protected_path(command: str, agent=None) -> bool:
    """True if a shell command both names a protected path and looks like it writes, or switches the guard plugin off.
    Two passes, either one is enough: the raw text (a protected name anywhere + a write anywhere), and the command as
    the shell would split it (quotes and escapes removed, `cd` followed, braces and patterns matched, interpreters fed
    by a here-document, `sh -c` strings) with only the paths each writer gets."""
    if command_disables_guard(command):
        return True
    frags = shell_protected_fragments(agent)
    if _shell_writes_protected(command, frags):
        return True
    if not any(_fragment_in(frag, command) for frag in frags) and not _glob_names_protected(command, frags):
        return False
    if _INLINE_PROGRAM.search(command) and _INLINE_WRITES.search(command):
        return True
    return bool(_WRITE_INDICATOR.search(_HARMLESS_REDIRECT.sub(" ", command)))


def _glob_names_protected(command: str, frags: list[str]) -> bool:
    """A shell pattern in the command that matches a protected folder whose name starts with a dot (.aegis, .claude,
    .codex): only those, since a pattern matches a dot name only when it starts with a dot itself, so `rm *.log` does
    not count."""
    import fnmatch
    dot_names = {part.lower() for f in frags for part in Path(f).parts if part.startswith(".") and len(part) > 2}
    for tok in _GLOB_TOKEN.findall(command):
        for part in tok.lower().split("/"):
            if part.startswith(".") and any(c in part for c in "*?[") and \
                    any(fnmatch.fnmatchcase(n, part) for n in dot_names):
                return True
    return False


# ---- the command as the shell splits it ------------------------------------------------------------------------------
# Text only, nothing runs: a path built at run time (`$(printf ...)`, a variable, a decoded string) stays unknown. An
# unknown piece next to a protected-looking name (`$(printf .%s aegis)/x`, `$D/settings.json`) counts as that name.

_SUB_OPEN, _SUB_CLOSE = "\x01", "\x02"              # around a substitution the text cannot resolve
_OPS = ("&&", "||", ";;", "|&", "<<<", "<<-", "<<", "&>>", ">>", ">|", "&>", ">&", "<&", "<>", ";", "&", "|", "(", ")",
        ">", "<")
_OP_RE = re.compile("|".join(re.escape(o) for o in _OPS))
_SEP = {"&&", "||", ";;", "|&", ";", "&", "|", "(", ")", "\n"}
_REDIR_OUT = {">", ">>", ">|", "&>", "&>>", "<>", ">&"}
# files in .aegis/ by name, so that a pattern or an unknown folder in front of one (`find . -name policy.json`) counts
_GUARD_RECORDS = ("policy.json", "config.json", "last_review.json", "acks.json", "indexes.json", "profile.json")
# file names specific enough that an unknown folder in front of them (`$D/settings.json`) is taken for a protected one
_DISTINCT_NAMES = {"settings.json", "settings.local.json", "policy.json", "hooks.json", "config.toml",
                   "last_review.json", "acks.json", "managed-settings.json"}
_WRAPPERS = {"sudo": "ughpCDrtU", "doas": "u", "env": "uCS", "exec": "a", "command": "", "builtin": "", "nohup": "",
             "time": "fo", "nice": "n", "ionice": "cnp", "xargs": "InPLdEsa", "busybox": "", "stdbuf": "ioe",
             "timeout": "sk", "unbuffer": "", "chronic": "", "setsid": "", "flock": "wE"}
_WRITERS = {"mv", "rm", "cp", "truncate", "tee", "chmod", "chown", "chgrp", "chattr", "dd", "ln", "link", "install",
            "rsync", "touch", "unlink", "rmdir", "shred", "patch", "zip", "unzip", "tar", "sponge", "split", "csplit",
            # editors: opened from the agent's shell they run a script (`vim -c`, `ex -sc`, `ed`) or write on exit
            "vi", "vim", "nvim", "ex", "ed", "emacs", "nano"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish"}
_INTERPRETER = re.compile(r"(?:python[\d.]*|pypy[\d.]*|node|nodejs|deno|bun|ruby|perl|php|lua|tclsh|Rscript|osascript)$",
                          re.I)
_GIT_WRITES = {"checkout", "restore", "reset", "apply", "am", "mv", "rm", "stash", "switch", "merge", "pull",
               "cherry-pick", "revert", "rebase"}


def _home() -> str:
    return os.path.expanduser("~")


def _subst(text: str, i: int) -> tuple[str, int]:
    """The `$...` / backtick at text[i]: $HOME and $PWD resolved, anything else kept as an unknown piece."""
    n = len(text)
    if text[i] == "`":
        j = text.find("`", i + 1)
        j = n if j < 0 else j
        return _SUB_OPEN + _plain(text[i + 1:j]) + _SUB_CLOSE, j + 1
    if text.startswith("$'", i):                    # $'\x2eaegis': ANSI-C quoting
        j = text.find("'", i + 2)
        j = n if j < 0 else j
        try:
            return text[i + 2:j].encode("latin-1", "backslashreplace").decode("unicode_escape"), j + 1
        except (UnicodeError, ValueError):
            return _SUB_OPEN + _plain(text[i + 2:j]) + _SUB_CLOSE, j + 1
    if text.startswith("$(", i):
        depth, j = 0, i + 1
        while j < n:
            depth += {"(": 1, ")": -1}.get(text[j], 0)
            if depth == 0:
                break
            j += 1
        return _SUB_OPEN + _plain(text[i + 2:j]) + _SUB_CLOSE, j + 1
    if text.startswith("${", i):
        j = text.find("}", i)
        j = n if j < 0 else j
        name, end = text[i + 2:j], j + 1
    else:
        m = re.match(r"[A-Za-z_]\w*|[0-9@*#?$!-]", text[i + 1:])
        if not m:
            return "$", i + 1
        name, end = m.group(), i + 1 + m.end()
    if name == "HOME":
        return _home(), end
    if name == "PWD":
        return ".", end
    return _SUB_OPEN + _plain(name) + _SUB_CLOSE, end


def _plain(s: str) -> str:
    return s.replace(_SUB_OPEN, " ").replace(_SUB_CLOSE, " ")


def _lex(text: str) -> list[tuple[str, str]]:
    """Shell words of `text` with quotes and escapes removed and ~ expanded: ("w", word), ("op", operator) - a newline
    is the operator "\\n" - and ("doc", body) for a here-document, placed after the newline that starts it."""
    out, i, n = [], 0, len(text)
    word, pending = None, []

    def flush():
        nonlocal word
        if word is not None:
            if out and out[-1] in (("op", "<<"), ("op", "<<-")):
                pending.append((word, out[-1][1] == "<<-"))
            out.append(("w", word))
            word = None

    while i < n:
        c = text[i]
        if c == "\\" and i + 1 < n:
            if text[i + 1] != "\n":
                word = (word or "") + text[i + 1]
            i += 2
        elif c in " \t\r":
            flush()
            i += 1
        elif c == "\n":
            flush()
            out.append(("op", "\n"))
            i += 1
            for delim, strip in pending:             # here-document bodies start on the next line
                body = []
                while i < n:
                    j = text.find("\n", i)
                    j = n if j < 0 else j
                    line, i = text[i:j], j + 1
                    if (line.lstrip("\t") if strip else line).rstrip("\r") == delim:
                        break
                    body.append(line)
                out.append(("doc", "\n".join(body)))
            pending = []
        elif c == "#" and word is None:
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "'":
            j = text.find("'", i + 1)
            j = n if j < 0 else j
            word = (word or "") + text[i + 1:j]
            i = j + 1
        elif c == '"':
            i, s = i + 1, ""
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n and text[i + 1] in '$`"\\\n':
                    s += text[i + 1] if text[i + 1] != "\n" else ""
                    i += 2
                elif text[i] in "$`":
                    t, i = _subst(text, i)
                    s += t
                else:
                    s += text[i]
                    i += 1
            word = (word or "") + s
            i += 1
        elif c in "$`":
            t, i = _subst(text, i)
            word = (word or "") + t
        elif c == "~" and word is None and (i + 1 == n or text[i + 1] in "/ \t\n;&|)"):
            word = _home()
            i += 1
        else:
            m = _OP_RE.match(text, i)
            op = m.group() if m else None
            if op is None:
                word = (word or "") + c
                i += 1
                continue
            if word is not None and word.isdigit() and op[0] in "<>":
                word = None                          # a file descriptor number (2>)
            flush()
            out.append(("op", op))
            i += len(op)
    flush()
    if pending:                                      # a here-document cut short: its text is the rest
        out.append(("doc", ""))
    return out


def _segments(tokens: list) -> list[dict]:
    """Simple commands: words, files written by a redirect, here-document / here-string text, fed by a pipe or not."""
    new = lambda piped=False: {"words": [], "out": [], "docs": [], "piped": piped, "stdin": False}  # noqa: E731
    segs, cur, expect, waiting = [], new(), None, []
    segs.append(cur)
    for kind, v in tokens:
        if kind == "doc":
            if waiting:
                waiting.pop(0)["docs"].append(v)
            continue
        if expect and kind == "w":
            if expect in _REDIR_OUT:
                cur["out"].append(v)
            elif expect == "<<<":
                cur["docs"].append(v)
            elif expect in ("<<", "<<-"):
                waiting.append(cur)
            else:
                cur["stdin"] = True
            expect = None
            continue
        expect = None
        if kind == "op" and v in _SEP:
            cur = new(v in ("|", "|&"))
            segs.append(cur)
        elif kind == "op":
            expect = v
        else:
            cur["words"].append(v)
    return segs


def _braces(word: str, limit: int = 32) -> list[str]:
    """{a,b} expanded the way the shell does (innermost first, at most `limit` words)."""
    m = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not m:
        return [word]
    out = []
    for alt in m.group(1).split(","):
        out += _braces(word[:m.start()] + alt + word[m.end():], limit)
        if len(out) >= limit:
            break
    return out[:limit]


def _resolve(path: str, cwd: str | None) -> str:
    if cwd and not path.startswith(("/", _SUB_OPEN)):
        path = cwd + "/" + path
    path = re.sub(r"/+", "/", path)
    return posixpath.normpath(path).lower() if path else path


def _targets(frags: list[str]) -> list[tuple[str, list[str]]]:
    """("in", parts): the protected path or anything under it; ("at", parts): a folder that holds one, which counts
    only when it is named itself (`rm -rf .claude`, `mv ~/.aegis x`), not a sibling inside it (.claude/worktrees)."""
    homes = {_home().rstrip("/").lower()}
    try:
        import pwd
        homes.add(pwd.getpwuid(os.getuid()).pw_dir.rstrip("/").lower())
    except (ImportError, KeyError, OSError):
        pass
    out = []
    for f in list(frags) + [".aegis/" + n for n in _GUARD_RECORDS]:
        parts = posixpath.normpath(re.sub(r"/+", "/", f.lower())).split("/")
        out.append(("in", parts))
        if parts[0] == "":                           # absolute: its folders, but not / , /top or the home folder
            out += [("at", parts[:k]) for k in range(3, len(parts)) if "/".join(parts[:k]) not in homes]
        else:
            out += [("at", parts[:k]) for k in range(1, len(parts)) if parts[k - 1].startswith(".")]
    seen, uniq = set(), []
    for t in out:
        key = (t[0], tuple(t[1]))
        if key not in seen:
            seen.add(key)
            uniq.append(t)
    return uniq


def _part_match(pat: str, name: str) -> int:
    """How a piece of a written path matches a piece of a protected one: 3 by name (literally, or a pattern / unknown
    piece that keeps at least three of its letters: `.ae*`, `setting[s].json`, `$(printf .%s aegis)`), 2 by a bare
    pattern (`*`, `*.x`), 1 by an unknown piece only (`$D`), 0 not at all. A pattern matches a dot name only when it
    starts with a dot (the shell's rule)."""
    import fnmatch
    if _SUB_OPEN in pat:
        glob = re.sub(re.escape(_SUB_OPEN) + ".*?" + re.escape(_SUB_CLOSE), "*", pat, flags=re.S)
        if not fnmatch.fnmatchcase(name, glob):
            return 0
        return 3 if any(w in name for w in re.findall(r"[a-z0-9_-]{3,}", pat)) else 1
    if any(c in pat for c in "*?["):
        if (name.startswith(".") and not pat.startswith(".")) or not fnmatch.fnmatchcase(name, pat):
            return 0
        return 3 if len(re.sub(r"\[[^]]*\]|[*?]", "", pat)) >= 3 else 2
    return 3 if pat == name else 0


def _path_hits(path: str, targets: list) -> bool:
    """Does `path` (resolved, lower case) name a protected file or folder, or a folder that holds one? At least one
    piece has to match by name; an unknown folder counts only in front of a file name specific to the guard or the
    agent's settings (`$D/settings.json`, not `$OUT/config.json`)."""
    parts = path.split("/")
    if not re.search(r"[*?\[\x01]", path) and not set(parts) & {p for _, t in targets for p in t}:
        return False                                 # the common case, a plain path naming nothing protected
    for kind, t in targets:
        if t[0] == "":                               # absolute: aligned at the start
            starts = [0] if parts[0] == "" else []
        elif kind == "at":
            starts = [len(parts) - len(t)]
        else:
            starts = range(len(parts) - len(t) + 1)
        for s in starts:
            if s < 0 or s + len(t) > len(parts) or (kind == "at" and s + len(t) != len(parts)):
                continue
            scores = []
            for k in range(len(t)):
                scores.append(_part_match(parts[s + k], t[k]))
                if not scores[-1]:
                    break
            if not all(scores) or 3 not in scores:
                continue
            if 1 not in scores or any(parts[s + k] == t[k] in _DISTINCT_NAMES for k in range(len(t))):
                return True
    return False


def _text_names(text: str, frags: list[str], targets: list) -> bool:
    """A program's text (python -c, a here-document) naming a protected path, folders that hold one included."""
    t = re.sub(r"/(?:\./)+", "/", re.sub(r"/+", "/", text.lower()))
    if any(_fragment_in(f.lower(), t) for f in frags) or _glob_names_protected(t, frags):
        return True
    return any(kind == "at" and len(p) == 1 and re.search(r"(?<![\w.-])" + re.escape(p[0]) + r"(?![\w./-])", t)
               for kind, p in targets)


def _agent_env_vars() -> set:
    """Environment variables that move an agent's config folder (adapters' CONFIG_ENV_VARS): set in front of the agent
    it starts an agent without the settings that load the guard."""
    from adapters import all_adapters
    return {v for a in all_adapters() for v in getattr(a, "CONFIG_ENV_VARS", ())}


def _shell_writes_protected(command: str, frags: list[str], cwd: str | None = None, depth: int = 0,
                            targets: list | None = None) -> bool:
    if depth > 4:
        return False
    targets = targets if targets is not None else _targets(frags)
    env_vars = _agent_env_vars()
    segs = _segments(_lex(command))
    docs = [d for s in segs for d in s["docs"]]
    program_writes = lambda text: bool(_INLINE_WRITES.search(text)) and _text_names(text, frags, targets)  # noqa: E731
    interpreter_seen = False
    for seg in segs:
        words = [x for w in seg["words"] for x in _braces(w)]
        paths = [(p, cwd) for o in seg["out"] for p in _braces(o)
                 if not re.fullmatch(r"\d+|-|/dev/(?:null|stdout|stderr|tty|fd/\d+)", p)]
        for w in seg["words"] + seg["out"]:          # $(...) / `...` run commands of their own
            for inner in re.findall(re.escape(_SUB_OPEN) + "(.*?)" + re.escape(_SUB_CLOSE), w, re.S):
                if _shell_writes_protected(inner, frags, cwd, depth + 1, targets):
                    return True
        i, assigns = 0, []
        while i < len(words) and re.match(r"[A-Za-z_]\w*=", words[i]):
            assigns.append(words[i])
            i += 1
        while i < len(words) and posixpath.basename(words[i]).lower() in _WRAPPERS:
            w = posixpath.basename(words[i]).lower()
            i += 1
            while i < len(words) and (words[i].startswith("-") or (w == "env" and re.match(r"[A-Za-z_]\w*=", words[i]))):
                if not words[i].startswith("-"):
                    assigns.append(words[i])
                elif len(words[i]) == 2 and words[i][1] in _WRAPPERS[w]:
                    i += 1                           # an option that takes a value (sudo -u root, xargs -I {})
                i += 1
            if w == "timeout" and i < len(words):
                i += 1                               # the duration
        if any(a.split("=", 1)[0] in env_vars for a in assigns):
            return True
        if i >= len(words):
            if any(_path_hits(_resolve(p, c), targets) for p, c in paths):
                return True
            continue
        cmd_word, args = words[i], words[i + 1:]
        cmd = posixpath.basename(cmd_word).lower()
        if cmd in ("export", "declare", "typeset", "readonly", "local") and \
                any(a.split("=", 1)[0] in env_vars for a in args if "=" in a):
            return True
        if cmd in ("cd", "pushd", "chdir"):
            dest = next((a for a in args if not a.startswith("-") or a == "-"), None)
            cwd = _home() if dest is None else None if dest == "-" else _resolve(dest, cwd)
            continue
        if cmd == "popd":
            cwd = None
            continue
        if cmd == "claude" and args[:1] in (["plugin"], ["plugins"]) and command_disables_guard(" ".join(["claude"] + args)):
            return True
        if cmd == "claude" and args[:1] == ["config"] and args[1:2] and args[1] in ("set", "add", "remove", "rm", "unset",
                                                                                     "reset"):
            keys = [a for a in args[2:] if not a.startswith("-")]
            if not keys or re.search(r"hook|plugin", keys[0], re.I):
                return True
        # the args a writer may write to, each with `x=y` also as y (dd of=, --target-directory=)
        writes = []
        if cmd in _WRITERS and not (cmd in ("vi", "vim", "nvim") and "-R" in args):
            writes = args
        elif cmd in ("sed", "gsed") and any(re.match(r"-[a-hj-zA-Z]*i", a) or a.startswith("--in-place") for a in args):
            writes = args
        elif cmd in ("awk", "gawk") and "inplace" in args:
            writes = args
        elif cmd in ("curl", "wget") and any(re.fullmatch(r"-[a-zA-Z]*[oOP]|--output(?:-document)?(?:=.*)?|"
                                                          r"--remote-name|--directory-prefix(?:=.*)?", a) for a in args):
            writes = args
        elif cmd == "git":
            gcwd, j = cwd, 0
            while j < len(args) and args[j].startswith("-"):
                if args[j] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env") \
                        and j + 1 < len(args):
                    if args[j] == "-C":
                        gcwd = _resolve(args[j + 1], gcwd)
                    j += 1
                j += 1
            sub, rest = (args[j], args[j + 1:]) if j < len(args) else ("", [])
            if sub == "clean":
                flags = [a for a in rest if a.startswith("-")]
                short = "".join(a[1:] for a in flags if re.fullmatch(r"-[a-zA-Z]+", a))
                force = "f" in short or "--force" in flags
                dry = "n" in short or "i" in short or {"--dry-run", "--interactive"} & set(flags)
                specs = [a for a in rest if not a.startswith("-")]
                if force and not dry:
                    # untracked and ignored files go: .aegis/, .claude/settings.local.json
                    if not specs or {".", "./", ":/", "*"} & set(specs):
                        return True
                    paths += [(s, gcwd) for s in specs]
            elif sub in _GIT_WRITES:
                paths += [(a, gcwd) for a in rest]
        elif cmd == "find":
            acts = {"-delete"} & set(args) or any(a in ("-exec", "-execdir", "-ok", "-okdir") and k + 1 < len(args) and
                                                  posixpath.basename(args[k + 1]).lower() in _WRITERS
                                                  for k, a in enumerate(args))
            if acts:
                starts = []
                for a in args:
                    if a.startswith(("-", "(", "!")):
                        break
                    starts.append(a)
                paths += [(s, cwd) for s in starts]
                names = {p for _, t in targets for p in t if p}
                for k, a in enumerate(args[:-1]):
                    pat = args[k + 1].lower()
                    if a in ("-name", "-iname"):
                        import fnmatch
                        if any(fnmatch.fnmatchcase(n, pat) for n in names):
                            return True
                    elif a in ("-path", "-ipath", "-wholename", "-iwholename") and _path_hits(_resolve(pat, None), targets):
                        return True
        elif cmd in _SHELLS or cmd == "eval":
            if cmd == "eval":
                if _shell_writes_protected(" ".join(args), frags, cwd, depth + 1, targets):
                    return True
            elif "-c" in args or any(re.fullmatch(r"-[a-zA-Z]*c", a) for a in args):
                k = next(k for k, a in enumerate(args) if re.fullmatch(r"-[a-zA-Z]*c", a))
                if k + 1 < len(args) and _shell_writes_protected(args[k + 1], frags, cwd, depth + 1, targets):
                    return True
            elif not [a for a in args if not a.startswith("-")]:     # the script comes on stdin
                if any(_shell_writes_protected(d, frags, cwd, depth + 1, targets) for d in seg["docs"]):
                    return True
        elif _INTERPRETER.match(cmd):
            interpreter_seen = True
            inline = any(re.fullmatch(r"-[a-zA-Z]*[ceE]|--eval|--command", a) or (cmd.startswith("php") and a == "-r")
                         for a in args)
            positional = [a for a in args if not a.startswith("-")]
            if inline and program_writes(" ".join(args)):
                return True
            if not inline and "-m" not in args and (not positional or positional[0] == "-"):
                # the program comes on stdin: a here-document, a here-string, or whatever is piped in
                program = "\n".join(seg["docs"]) + ("\n" + command if seg["piped"] or seg["stdin"] else "")
                if program_writes(program):
                    return True
            if "-m" in args and "pip" in args:
                cmd = "pip"
        if cmd.startswith("pip") or cmd in ("uv", "npm", "pnpm", "yarn"):
            for k, a in enumerate(args):
                key, _, val = a.partition("=")
                if key in ("-t", "--target", "--prefix", "--root", "--src", "--user-base"):
                    paths.append((val or (args[k + 1] if k + 1 < len(args) else ""), cwd))
        # a program run from inside a protected folder that installs there (`cd ~/.aegis/ml/venv && bin/pip install`)
        if "/" in cmd_word and _path_hits(_resolve(cmd_word, cwd), targets) and \
                {"install", "uninstall", "add", "remove", "update", "upgrade", "ci"} & set(args):
            return True
        paths += [(p, cwd) for a in writes for p in ([a] + ([a.split("=", 1)[1]] if "=" in a else []))]
        if any(_path_hits(_resolve(p, c), targets) for p, c in paths if p):
            return True
    # a script written by a here-document and run in the same command (`cat > w.py <<X ... X; python3 w.py`)
    return interpreter_seen and any(program_writes(d) for d in docs)


def _path_text(p: str) -> str:
    """A file path the way the protected-path fragments are matched: `//` and `/./` collapsed, `..` resolved, lower
    case (a case-insensitive file system opens .AEGIS/policy.json as .aegis/policy.json)."""
    p = re.sub(r"/+", "/", p)
    return (posixpath.normpath(p) if p not in ("", ".") else p).lower()


def file_path_is_protected(file_path: str, agent=None) -> bool:
    """True if a file edit targets a protected file (also spelled `.claude//settings.json`, `.AEGIS/policy.json`)."""
    p = _path_text(file_path)
    return any(frag in file_path or frag.lower() in p for frag in protected_fragments(agent))


def file_path_is_mcp_config(file_path: str, agent=None) -> bool:
    """True if the path is an MCP server config of the running agent or of any agent agent_formats.json knows."""
    if Path(file_path).name in getattr(_agent(agent), "MCP_CONFIG_NAMES", ()):
        return True
    import agent_config
    return any(kind == "mcp" for _, kind, _ in agent_config.specs_for(file_path))
