"""
AegisPilot - rule modules layered on the base rules.

The base rules (guard/rules/*.json) are the team's and change with the guard. A person or an administrator adds their own
on top without touching them, one JSON file per module:
  ~/.aasm/rules/*.json      the user's modules (a protected path: an agent that writes one is stopped like one that
                            edits the guard). Not read by a system install (a guard the user cannot write), like
                            ~/.aasm/config.json (switches.py).
  /etc/aasm/rules/*.json    the administrator's modules: read only when the folder and the file are owned by root and
                            not writable by group or others. Applied after the user's, so they win.
Files are applied in name order. A module that is not valid JSON, uses an unknown key, names something that does not
exist, or leaves rules the engine cannot load is skipped as a whole and reported (guard_cli verify, rule_check
--modules); the guard keeps running on the rest.

A module ({"schema": 1, "name": ..., "about": ..., then any of}):
  "signals":    {name: signal}                 add a signal of signals.json, or replace the one with that name
  "rules":      [rule]                         add a rule of rules.json, or replace the one with the same id
  "hard_rules": [hard rule]                    the same for scoring.json hard_rules (a new one is tried last)
  "post_rules": [rule]                         the same for post.json rules (a new one is tried last)
  "findings":   {finding: {auto, call, ...}}   change the behavior policy (rules/behavior.json) of an existing finding
  "set":        {"<file>.<key>.<key>": value}  set one value, e.g. "scoring.thresholds.review": 0.2
  "add":        {"<file>.<key>.<key>": [..]}   extend a list, e.g. "scoring.subscores.typosquat.popular_names"
  "disable":    {"rules"|"hard_rules"|"post_rules"|"findings": [id]}   switch base entries off
  "examples":   {"static"|"hard"|"post": {id: [case]}}   the module's own examples (rule_check --modules runs them)
<file> is one of signals, rules, scoring, post, behavior.
"""
from __future__ import annotations

import copy
import json
import os
import stat
from pathlib import Path

SYSTEM_DIR = Path("/etc/aasm/rules")
FILES = ("signals", "rules", "scoring", "post", "behavior")
KEYS = {"schema", "name", "about", "signals", "rules", "hard_rules", "post_rules", "findings", "set", "add", "disable",
        "examples"}
DISABLE_KINDS = ("rules", "hard_rules", "post_rules", "findings")


class ModuleError(Exception):
    pass


def user_dir() -> Path:
    return Path.home() / ".aasm" / "rules"


def _trusted(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return False
    return st.st_uid == 0 and not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)


def module_files() -> tuple[list[tuple[str, Path]], list[dict]]:
    """([(origin, file)] in the order they apply, [skipped file reports])."""
    import switches
    out, skipped = [], []
    if switches.get("AASM_RULE_MODULES", "1") == "0":
        return out, skipped
    if os.access(switches.GUARD_DIR, os.W_OK):           # a system install does not follow the user's modules
        d = user_dir()
        if d.is_dir():
            out += [("user", f) for f in sorted(d.glob("*.json"))]
    if SYSTEM_DIR.is_dir():
        if not _trusted(SYSTEM_DIR):
            skipped.append({"origin": "admin", "file": str(SYSTEM_DIR), "status": "skipped",
                            "error": "folder is not owned by root or is writable by other users"})
        else:
            for f in sorted(SYSTEM_DIR.glob("*.json")):
                if _trusted(f):
                    out.append(("admin", f))
                else:
                    skipped.append({"origin": "admin", "file": str(f), "status": "skipped",
                                    "error": "file is not owned by root or is writable by other users"})
    return out, skipped


def _by_id(items: list, new: list, what: str) -> int:
    """Replace the entry with the same id in place, else append. Returns how many were added."""
    added = 0
    for item in new:
        if not isinstance(item, dict) or not item.get("id"):
            raise ModuleError(f"{what}: every entry needs an id")
        at = next((i for i, x in enumerate(items) if x.get("id") == item["id"]), None)
        if at is None:
            items.append(copy.deepcopy(item))
            added += 1
        else:
            items[at] = copy.deepcopy(item)
    return added


def _walk(docs: dict, dotted: str):
    """(the dict that holds the last key, the last key) of "<file>.<key>...", every parent must exist."""
    parts = dotted.split(".")
    if len(parts) < 2 or parts[0] not in FILES or docs.get(parts[0]) is None:
        raise ModuleError(f"'{dotted}': must be <file>.<key> (files: {', '.join(FILES)})")
    node = docs[parts[0]]
    for p in parts[1:-1]:
        if not isinstance(node, dict) or p not in node:
            raise ModuleError(f"'{dotted}': '{p}' does not exist")
        node = node[p]
    if not isinstance(node, dict):
        raise ModuleError(f"'{dotted}': not a place a value can be set")
    return node, parts[-1]


def apply_module(docs: dict, mod: dict) -> dict:
    """Apply one module to `docs` (changed in place). Returns a short summary of what it changed."""
    if not isinstance(mod, dict):
        raise ModuleError("not a JSON object")
    if mod.get("schema") != 1:
        raise ModuleError(f"schema must be 1 (got {mod.get('schema')!r})")
    unknown = set(mod) - KEYS
    if unknown:
        raise ModuleError(f"unknown keys: {', '.join(sorted(unknown))}")
    done: dict[str, int] = {}
    if "signals" in mod:
        if not isinstance(mod["signals"], dict):
            raise ModuleError("signals must be {name: signal}")
        docs["signals"].setdefault("signals", {}).update(copy.deepcopy(mod["signals"]))
        done["signals"] = len(mod["signals"])
    for key, holder, field in (("rules", "rules", "rules"), ("hard_rules", "scoring", "hard_rules"),
                               ("post_rules", "post", "rules")):
        if key in mod:
            if not isinstance(mod[key], list):
                raise ModuleError(f"{key} must be a list")
            _by_id(docs[holder].setdefault(field, []), mod[key], key)
            done[key] = len(mod[key])
    if "findings" in mod:
        if docs.get("behavior") is None:
            raise ModuleError("findings: behavior policy (behavior.json) is missing")
        base = docs["behavior"]["findings"]
        for name, change in mod["findings"].items():
            if name not in base:
                raise ModuleError(f"findings: unknown behavior '{name}' (only findings the analyzer produces can be changed)")
            if not isinstance(change, dict) or set(change) - {"auto", "call", "label", "text", "phases"}:
                raise ModuleError(f"findings.{name}: only auto, call, label, text, phases can be changed")
            for k in ("auto", "call"):
                if k in change and change[k] not in ("block", "review", None):
                    raise ModuleError(f"findings.{name}.{k}: must be block, review or null")
            base[name].update(copy.deepcopy(change))
        done["findings"] = len(mod["findings"])
    for dotted, value in (mod.get("set") or {}).items():
        node, last = _walk(docs, dotted)
        if last not in node:
            raise ModuleError(f"set '{dotted}': no such key (set does not create new keys)")
        node[last] = copy.deepcopy(value)
        done["set"] = done.get("set", 0) + 1
    for dotted, items in (mod.get("add") or {}).items():
        node, last = _walk(docs, dotted)
        if not isinstance(node.get(last), list) or not isinstance(items, list):
            raise ModuleError(f"add '{dotted}': can only add to a list")
        node[last] += [x for x in items if x not in node[last]]
        done["add"] = done.get("add", 0) + 1
    off = mod.get("disable") or {}
    if set(off) - set(DISABLE_KINDS):
        raise ModuleError(f"disable: only {', '.join(DISABLE_KINDS)}")
    for kind, ids in off.items():
        if kind == "findings":
            base = (docs.get("behavior") or {}).get("findings", {})
            for name in ids:
                if name not in base:
                    raise ModuleError(f"disable.findings: unknown behavior '{name}'")
                base[name]["auto"] = base[name]["call"] = None
        else:
            holder, field = {"rules": ("rules", "rules"), "hard_rules": ("scoring", "hard_rules"),
                             "post_rules": ("post", "rules")}[kind]
            items = docs[holder].get(field, [])
            missing = set(ids) - {x.get("id") for x in items}
            if missing:
                raise ModuleError(f"disable.{kind}: unknown ids {', '.join(sorted(missing))}")
            docs[holder][field] = [x for x in items if x.get("id") not in ids]
        done[f"disable.{kind}"] = len(ids)
    return done


def apply(docs: dict, validate) -> tuple[dict, list[dict]]:
    """Layer every module on `docs` (the base rule files as loaded). `validate(candidate)` raises when the rules can
    not be loaded; a module that fails anything is skipped whole. Returns (docs with the modules, one report per file)."""
    files, report = module_files()
    for origin, path in files:
        entry = {"origin": origin, "file": str(path), "name": path.stem}
        try:
            mod = json.loads(path.read_text(encoding="utf-8"))
            entry["name"] = str(mod.get("name") or path.stem) if isinstance(mod, dict) else path.stem
            candidate = copy.deepcopy(docs)
            entry["changes"] = apply_module(candidate, mod)
            validate(candidate)
        except Exception as e:                           # any failure skips the whole module
            entry.update(status="skipped", error=f"{type(e).__name__}: {e}"[:300])
            report.append(entry)
            continue
        docs = candidate
        entry["status"] = "applied"
        entry["examples"] = mod.get("examples") or {}
        report.append(entry)
    return docs, report
