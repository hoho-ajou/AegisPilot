"""
AegisPilot - what a Python interpreter command line runs.

`python -m pip install x` installs x; so do `python -I -m pip install x`, `python -Im pip install x`,
`python -W ignore -X utf8 -m pip install x` and `py -3.12 -m pip install x`. Every place that asks "is this python running
pip (or uv)?" reads the command line here, with Python's own option rules, instead of checking that `-m` comes first:
an agent that ran `.venv/bin/python -I -m pip install pendulum` installed a deny-listed package unseen (2026-11-16).
"""
from __future__ import annotations

# interpreter options that take the next token as their value (or the rest of the same token: `-Wignore`)
_VALUE_CHARS = {"W", "X"}
_VALUE_LONG = {"--check-hash-based-pycs"}


def module_args(rest: list[str]) -> tuple[str, list[str]] | None:
    """For `python <rest...>`: (module, its arguments) when the command runs a module with -m; None when it runs a
    script, inline code (-c), reads the program from stdin, or the line ends first. Interpreter options before -m
    (-I -E -s -S -u -B -O -OO -q -b -bb -d -v -x -P, -W/-X with their value, the launcher's -3.12) are skipped,
    bundled ones too (`-Im`, `-IBm pip`, `-mpip`)."""
    i = 0
    while i < len(rest):
        tok = rest[i]
        if tok in _VALUE_LONG:
            i += 2
            continue
        if tok.startswith("--check-hash-based-pycs="):
            i += 1
            continue
        if tok == "--" or tok == "-" or not tok.startswith("-"):
            return None                     # a script path, stdin, or the end of the options
        if tok.startswith("--"):
            i += 1                          # --help / --version and the like: no value
            continue
        body = tok[1:]
        skip_value = False
        for j, ch in enumerate(body):
            if ch == "m":
                attached = body[j + 1:]
                if attached:
                    return attached, rest[i + 1:]
                return (rest[i + 1], rest[i + 2:]) if i + 1 < len(rest) else None
            if ch == "c":
                return None                 # inline code: the program is the next token, not a module
            if ch in _VALUE_CHARS:
                skip_value = not body[j + 1:]   # `-W ignore` (value next) vs `-Wignore` (value attached)
                break
        i += 2 if skip_value else 1
    return None


def runs_module(rest: list[str], *names: str) -> list[str] | None:
    """The module's arguments when `python <rest...>` runs one of `names` (`pip`, `uv`), else None."""
    got = module_args(rest)
    return got[1] if got and got[0] in names else None
