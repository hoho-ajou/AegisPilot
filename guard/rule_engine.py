"""
Rule engine: applies the rule files in guard/rules/ to an unpacked package and turns the result into a verdict.

The rule files hold every value - what to look for (signals.json), where and how to look and which evidence to leave
(rules.json), how the findings become a verdict (scoring.json), and the rules applied after the scan plus the release
comparison (post.json, used by post_rules.py and version_diff.py). This module only knows the *kinds* of check
(detectors) and how to run them; changing a pattern, a window, a weight, a threshold, a hard rule's order or its
reason text is a rule-file edit. A new kind of check (a new detector) is the only thing that needs code here.

The detectors and the scoring reproduce what scan_engine.py did before the rules moved out: same evidence, same
order, same verdicts and scores. The ML model and its features stay outside the rule files; scoring.json only says
how much its score counts.
"""
from __future__ import annotations

import base64
import bisect
import hashlib
import json
import math
import os
import re
from collections import Counter
from pathlib import Path

import switches  # noqa: E402  (AASM_RULES_DIR: a built guard reads it from the system config only)
RULES_DIR = Path(switches.get("AASM_RULES_DIR") or str(Path(__file__).resolve().parent / "rules"))
DETECTORS = {"startup", "keyword_count", "chain", "entropy_blocks", "first_line", "setup_local_imports", "placement"}
PLACEMENT_CHECKS = {"command_shadowing", "sourceless_bytecode", "environment_index"}
POST_CHECKS = {"known_malicious", "new_risky_code", "late_file", "osv_unavailable", "typosquat", "new_package"}
VERDICTS = {"ALLOW", "NEEDS_HUMAN_REVIEW", "BLOCK"}
FILES = ("signals", "rules", "scoring", "post")


class RulesetError(Exception):
    """A rule file is missing, malformed, or refers to something that does not exist."""


# ----------------------------------------------------------------------------- loading

def _compile_signal(name: str, spec: dict) -> list[re.Pattern]:
    pats = []
    bare = set(spec.get("bare_builtins", []))
    for lit in spec.get("literals", []):
        pats.append(re.compile((r"(?<![\w.])" if lit in bare else "") + re.escape(lit)))
    for item in spec.get("regex", []):
        if isinstance(item, str):
            item = {"pattern": item}
        flags = (re.IGNORECASE if item.get("ignorecase") else 0) | (re.MULTILINE if item.get("multiline") else 0)
        try:
            pats.append(re.compile(item["pattern"], flags))
        except (re.error, KeyError) as e:
            raise RulesetError(f"signals.json: signal '{name}' has a bad pattern: {e}") from None
    if not pats:
        raise RulesetError(f"signals.json: signal '{name}' has no literals or regex")
    return pats


class Ruleset:
    def __init__(self, signals: dict, rules: dict, scoring: dict, post: dict, source: Path):
        self.source = source
        self.raw = {"signals": signals, "rules": rules, "scoring": scoring, "post": post}
        self.signals = {n: _compile_signal(n, s) for n, s in signals.get("signals", {}).items()}
        self.keyword_literals = {n: list(s.get("literals", [])) for n, s in signals.get("signals", {}).items()}
        # "quick": lowercase substrings at least one of which every match contains. A file with none of them is skipped
        # without running the patterns (case-insensitive alternations are slow on large files in Python's re)
        self.quick = {n: [q.lower() for q in s["quick"]] for n, s in signals.get("signals", {}).items() if s.get("quick")}
        # "lowercase": the patterns are written in lower case and run on the lowercased text (case-sensitive patterns
        # that start with a word use re's fast literal search; ignorecase alternations do not)
        self.lowercase = {n for n, s in signals.get("signals", {}).items() if s.get("lowercase")}
        paths = signals.get("paths", {})
        try:
            self.test_path = re.compile(paths["test"]["regex"])
            self.dev_toplevel = set(paths["dev_toplevel"]["names"])
            self.startup_py = tuple(paths["startup_py"]["names"])
            tf = paths.get("text_files", {})
            self.text_suffixes = {x.lower() for x in tf.get("suffixes", [])}
            self.text_names = {x.lower() for x in tf.get("names", [])}
            self.text_max_bytes = int(tf.get("max_bytes", 0))
        except (KeyError, re.error) as e:
            raise RulesetError(f"signals.json: paths section is incomplete: {e}") from None
        # languages: which files are code of which language (rules say which languages they read, default python);
        # ecosystems: which languages run in a kind of scan (a PyPI package runs Python; an npm package JavaScript and
        # its lifecycle shell commands; a bundle - skill, plugin, hook - any of them) and whether test/maintenance
        # folders are skipped. A file in a language the scan's ecosystem does not run is only read by "text" rules.
        langs = signals.get("languages") or {"python": {"suffixes": [".py"]}}
        self.lang_of_suffix = {}
        self.lang_code_view = {}       # language -> (comment line prefixes, message-command regex): what never runs
        for lang, spec in langs.items():
            if lang == "about":
                continue
            for suf in spec.get("suffixes", []):
                self.lang_of_suffix[suf.lower()] = lang
            prefixes = tuple(spec.get("comment_prefixes", []))
            msg = spec.get("message_commands", [])
            msg_rx = re.compile(r"(?<![\w$-])(?:" + "|".join(map(re.escape, msg)) + r")\s+(?:-[a-zA-Z]+\s+)*"
                                r"(\"(?:[^\"\\]|\\.)*\"|'[^']*')(?!\s*\|)") if msg else None   # piped on: not a message
            if prefixes or msg_rx:
                self.lang_code_view[lang] = (prefixes, msg_rx)
        self.languages = set(self.lang_of_suffix.values())
        ecos = signals.get("ecosystems") or {"pypi": {"code": ["python"], "skip_test_and_dev": True}}
        self.ecosystems = {}
        for eco, spec in ecos.items():
            if eco == "about":
                continue
            unknown = set(spec.get("code", [])) - self.languages
            if unknown:
                raise RulesetError(f"signals.json: ecosystem '{eco}' names unknown languages {sorted(unknown)}")
            self.ecosystems[eco] = {"code": set(spec.get("code", [])), "skip_test_and_dev": bool(spec.get("skip_test_and_dev", True)),
                                    "dev_names": {n.lower() for n in spec["dev_names"]} if "dev_names" in spec else None}
        if "pypi" not in self.ecosystems:
            raise RulesetError("signals.json: ecosystems needs 'pypi'")
        self.common_commands = {c.lower() for c in signals.get("commands", {}).get("common", [])}
        al = signals.get("aliases", {})
        self.alias_modules = set(al.get("modules", []))
        self.alias_call_targets = set(al.get("call_targets", []))
        self.alias_all_functions_of = set(al.get("all_functions_of", []))
        self.alias_builtins = set(al.get("builtins", []))
        sl = signals.get("string_literals", {})
        self.payload_families = [self.sig(n) for n in sl.get("payload_signals", [])]
        self.max_literal_scan_bytes = int(sl.get("max_scan_bytes", 1024 * 1024))

        self.max_evidence = int(rules.get("max_evidence_per_rule", 3))
        self.snippet_max = int(rules.get("snippet_max", 120))
        self.rules = list(rules.get("rules", []))
        self.windows = {}
        self.rule_langs: dict[str, set] = {}
        for r in self.rules:
            if r.get("detector") not in DETECTORS:
                raise RulesetError(f"rules.json: rule '{r.get('id')}' has unknown detector '{r.get('detector')}'")
            for key in ("signal", "first", "then", "risky", "exec_lines", "keywords"):
                v = r.get(key)
                if isinstance(v, str) and v != "all" and v not in self.signals:
                    raise RulesetError(f"rules.json: rule '{r['id']}' refers to unknown signal '{v}'")
            for pair in r.get("chains", []):
                for v in pair:
                    if v not in self.signals:
                        raise RulesetError(f"rules.json: rule '{r['id']}' refers to unknown signal '{v}'")
            if "within_lines" in r:
                self.windows[r["id"]] = int(r["within_lines"])
            langs = r.get("lang", "python")
            langs = {langs} if isinstance(langs, str) else set(langs)
            if not langs or langs - self.languages:
                raise RulesetError(f"rules.json: rule '{r['id']}' names unknown languages {sorted(langs - self.languages)}")
            self.rule_langs[r["id"]] = langs
            if r.get("detector") == "placement" and r.get("check") not in PLACEMENT_CHECKS:
                raise RulesetError(f"rules.json: rule '{r['id']}' placement check must be one of {sorted(PLACEMENT_CHECKS)}")
            near = r.get("unless_near")
            if near is not None and (not isinstance(near, dict) or near.get("signal") not in self.signals):
                raise RulesetError(f"rules.json: rule '{r['id']}' unless_near needs a known signal")
            if "evidence" in r and not (isinstance(r["evidence"], str) and r["evidence"]):
                raise RulesetError(f"rules.json: rule '{r['id']}' evidence must be an evidence id")
            if r.get("files") == "text" and (r["detector"] != "first_line" or r.get("text") != "original"):
                raise RulesetError(f"rules.json: rule '{r['id']}' files \"text\" works with detector first_line and text \"original\"")
            if r.get("files") == "text" and not self.text_max_bytes:
                raise RulesetError(f"rules.json: rule '{r['id']}' needs signals.json paths.text_files")
            if r.get("skip_docstrings") and r.get("text") != "original":
                raise RulesetError(f"rules.json: rule '{r['id']}' skip_docstrings needs text \"original\"")
        ids = Counter(r["id"] for r in self.rules)
        dup = [i for i, n in ids.items() if n > 1]
        if dup:
            raise RulesetError(f"rules.json: duplicate rule id {dup}")

        self.scoring = scoring
        try:
            th = scoring["thresholds"]
            self.block_threshold = float(th["block"])
            self.review_threshold = float(th["review"])
            self.review_floor = self.review_threshold + float(th["review_floor_margin"])
            self.weights = {k: float(v) for k, v in scoring["weights"].items()}
            self.sub = scoring["subscores"]
            self.hard_rules = list(scoring["hard_rules"])
            self.ml_weight = float(scoring["ml"]["weight"])
            self.ml_subscores = list(scoring["ml"]["subscores"])
        except (KeyError, TypeError, ValueError) as e:
            raise RulesetError(f"scoring.json: missing or bad value: {e}") from None
        produced = {evidence_id(r) for r in self.rules} | {v for r in self.rules for v in r.get("evidence_ids", {}).values()}

        def evidence_refs(c: dict):
            for sub in c.get("all", []) + c.get("any", []):
                yield from evidence_refs(sub)
            if "evidence" in c:
                yield c["evidence"]
        for h in self.hard_rules:
            for ref in evidence_refs(h.get("when", {})):
                if ref not in produced:
                    raise RulesetError(f"scoring.json: hard rule '{h.get('id')}' refers to evidence '{ref}' that no rule leaves")
            if h.get("action") not in ("block", "review"):
                raise RulesetError(f"scoring.json: hard rule '{h.get('id')}' has unknown action '{h.get('action')}'")
            if h.get("window_from") and h["window_from"] not in self.windows:
                raise RulesetError(f"scoring.json: hard rule '{h['id']}' window_from refers to unknown rule")
        self._load_post(post)

    def _load_post(self, post: dict) -> None:
        """post.json: the rules applied after the scan (post_rules.py) and the release comparison (version_diff.py)."""
        def rx(where: str, pattern, flags=0) -> re.Pattern:
            try:
                return re.compile(pattern, flags)
            except (re.error, TypeError) as e:
                raise RulesetError(f"post.json: {where} has a bad pattern: {e}") from None
        self.post_rules = list(post.get("rules", []))
        for r in self.post_rules:
            if r.get("id") not in POST_CHECKS:
                raise RulesetError(f"post.json: unknown rule '{r.get('id')}' (known: {', '.join(sorted(POST_CHECKS))})")
            if r.get("verdict") not in VERDICTS:
                raise RulesetError(f"post.json: rule '{r['id']}' has unknown verdict '{r.get('verdict')}'")
            to = r.get("applies_to")
            if to != "any" and not (isinstance(to, list) and to and set(to) <= VERDICTS):
                raise RulesetError(f"post.json: rule '{r['id']}' applies_to must be \"any\" or a list of verdicts")
        dup = [i for i, n in Counter(r["id"] for r in self.post_rules).items() if n > 1]
        if dup:
            raise RulesetError(f"post.json: duplicate rule id {dup}")
        try:
            km = post["known_malicious"]
            self.malicious_id_prefixes = tuple(km["id_prefixes"])
            self.malicious_text = rx("known_malicious.text_regex", km["text_regex"],
                                     re.IGNORECASE if km.get("text_ignorecase") else 0)
            self.malicious_details_chars = int(km["details_chars"])
            self.malicious_max_ids = int(km["max_ids"])
            self.typosquat_established_days = int(post["typosquat"]["established_days"])
            self.new_package_days = int(post["new_package"]["days"])
            pr = post["osv_probe"]
            self.osv_probe = (str(pr["name"]), str(pr["version"]))
            self.osv_probe_timeout = float(pr["timeout_seconds"])
            vd = post["version_diff"]
            self.vd = vd
            self.vd_skip = rx("version_diff.skip_paths", vd["skip_paths"])
            self.vd_prerelease = rx("version_diff.prerelease", vd["prerelease"], re.IGNORECASE)
            it = vd["import_time"]
            self.vd_danger_prefixes = tuple(it["danger_prefixes"])
            self.vd_constant_ok = tuple(it["constant_arg_ok_prefixes"])
            self.vd_builtin_names = dict(it["builtin_names"])
            self.vd_quick = rx("version_diff.import_time.quick", it["quick"])
            self.vd_quick_added = rx("version_diff.import_time.quick_added_extra", it["quick"] + it["quick_added_extra"])
            ep = vd["encoded_payload"]
            self.vd_blob = rx("version_diff.encoded_payload.blob", ep["blob"])
            self.vd_blob_with = rx("version_diff.encoded_payload.with", ep["with"])
            for key in ("recent_days", "max_bisect_steps", "max_file_bytes", "max_signals"):
                int(vd[key])
            bp = vd["binary_py"]
            int(bp["head_lines"]), int(bp["max_replacement_chars"]), list(bp["contains"]), list(bp["starts_with"])
            int(vd["new_pth"]["detail_max"]), str(vd["new_pth"]["line_prefix"])
            tr = post["transitive"]
            self.transitive = {k: int(tr[k]) for k in ("recent_days", "max_depth", "max_packages", "max_scans", "workers",
                                                        "budget_seconds")}
            if min(self.transitive.values()) < 0 or self.transitive["workers"] < 1:
                raise ValueError("transitive values must be positive")
            lf = post["late_file"]
            self.late_min_days, self.late_within_days = int(lf["min_days_late"]), int(lf["within_days"])
        except (KeyError, TypeError, ValueError) as e:
            raise RulesetError(f"post.json: missing or bad value: {e}") from None

    def sig(self, name: str) -> list[re.Pattern]:
        return self.signals[name]

    def may_match(self, name: str, text: str, lower: str | None = None) -> bool:
        """False only when the signal has a "quick" list and none of it is in `text`."""
        q = self.quick.get(name)
        if not q:
            return True
        low = lower if lower is not None else text.lower()
        return any(x in low for x in q)

    def window_of(self, rule_id: str) -> int:
        return self.windows[rule_id]


def _build(parts: dict, d: Path) -> Ruleset:
    rs = Ruleset(parts["signals"], parts["rules"], parts["scoring"], parts["post"], d)
    rs.raw["behavior"] = parts.get("behavior")
    if parts.get("behavior") is not None:                # the behavior policy must load too (behavior/values.Policy)
        from behavior.values import Policy
        Policy(doc=parts["behavior"])
    return rs


def load(rules_dir: Path | str = RULES_DIR, modules: bool = False) -> Ruleset:
    """The rule files of `rules_dir`; with modules=True also the user's and administrator's rule modules on top
    (rule_modules.py). rs.modules says which were applied or skipped and why."""
    d = Path(rules_dir)
    parts = {}
    for name in FILES + ("behavior",):
        f = d / f"{name}.json"
        try:
            parts[name] = json.loads(f.read_text(encoding="utf-8"))
        except FileNotFoundError:
            if name == "behavior":                       # optional: older rule folders (tests) have none
                parts[name] = None
                continue
            raise RulesetError(f"rule file missing: {f}") from None
        except ValueError as e:
            raise RulesetError(f"{f.name} is not valid JSON: {e}") from None
        if parts[name].get("schema") != 1:
            raise RulesetError(f"{f.name}: unsupported schema {parts[name].get('schema')!r}")
    report = []
    if modules:
        import rule_modules
        parts, report = rule_modules.apply(parts, lambda candidate: _build(candidate, d))
    rs = _build(parts, d)
    rs.modules = report
    rs.fingerprint = hashlib.sha256(json.dumps(parts, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
    return rs


_current: Ruleset | None = None


def current() -> Ruleset:
    """The rules every guard module uses (RULES_DIR + rule modules), loaded once per process."""
    global _current
    if _current is None:
        _current = load(modules=True)
    return _current


# ----------------------------------------------------------------------------- text helpers (moved from scan_engine)

def evidence_id(rule: dict) -> str:
    """The evidence id a rule leaves: its own id, or "evidence" - a rule for another language that finds the same
    thing (a JavaScript decode-then-eval is decode_then_exec) shares its evidence, so the hard rules, the report wording
    and the attack-path meaning of that evidence apply without being repeated."""
    return rule.get("evidence") or rule["id"]


def text_lines_of(path: Path) -> list[str]:
    try:
        return path.read_text(errors="ignore").splitlines()
    except OSError:
        return []


_SHEBANG_LANG = {"python": "python", "pypy": "python", "sh": "shell", "bash": "shell", "zsh": "shell", "dash": "shell",
                 "ksh": "shell", "node": "js", "nodejs": "js", "deno": "js", "bun": "js"}


def lang_of(rs: "Ruleset", path: Path) -> str | None:
    """The language of a file: its suffix, or for a file without one (a script in bin) its #! line."""
    lang = rs.lang_of_suffix.get(path.suffix.lower())
    if lang or path.suffix:
        return lang
    try:
        with open(path, "rb") as fh:
            head = fh.read(128)
    except OSError:
        return None
    if not head.startswith(b"#!"):
        return None
    words = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").split()
    if words and Path(words[0]).name == "env":
        words = [w for w in words[1:] if not w.startswith("-")]
    name = Path(words[0]).name if words else ""
    return next((lang for prefix, lang in _SHEBANG_LANG.items() if name == prefix or re.fullmatch(re.escape(prefix) + r"[\d.]*", name)), None)


def code_view(rs: "Ruleset", lang: str | None, lines: list[str]) -> list[str] | None:
    """The lines as the code rules should see them, or None when the language needs no change: comment lines blanked and
    the text a message command prints (`echo "…"`) blanked - neither runs. Line count and offsets stay the same."""
    view = rs.lang_code_view.get(lang)
    if view is None:
        return None
    prefixes, msg_rx = view
    out = []
    for line in lines:
        if prefixes and line.lstrip().startswith(prefixes):
            out.append("")
            continue
        if msg_rx is not None and msg_rx.search(line):
            line = msg_rx.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + " " * len(m.group(1)), line)
        out.append(line)
    return out


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def package_relative(path: Path) -> str:
    """Strip the temp extraction dir: <tmp>/<archive>.unpacked/<pkg-root>/a/b.py -> a/b.py"""
    parts = path.parts
    for i, part in enumerate(parts):
        if part.endswith(".unpacked"):
            rest = parts[i + 1:]
            # an sdist (.tar.gz or .zip) has one top-level <name>-<ver>/ dir; a wheel does not
            if not part.endswith(".whl.unpacked") and len(rest) > 1:
                rest = rest[1:]
            return "/".join(rest)
    return path.name


def archive_depth(path: Path) -> int:
    """Path length below the `<archive>.unpacked` directory (1 = at the archive root); 0 if not inside one."""
    parts = path.parts
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].endswith(".unpacked"):
            return len(parts) - 1 - i
    return 0


_SCHEMES = {"purelib": "site", "platlib": "site", "scripts": "bin", "data": "prefix", "headers": "headers"}


def installed_place(path: Path) -> tuple[str, str] | None:
    """Where a wheel member ends up once pip installs it (the wheel format, PEP 427): ("site", rel) in site-packages,
    ("bin", name) for <dist>.data/scripts, ("prefix", rel) for <dist>.data/data (the environment root), ("headers", rel);
    None outside a wheel (an sdist is built, not copied). The rules use the place, not path strings: an attacker who
    moves a file elsewhere moves it to where nothing runs it."""
    parts = path.parts
    i = next((k for k in range(len(parts) - 1, -1, -1) if parts[k].endswith(".whl.unpacked")), None)
    if i is None:
        return None
    rel = parts[i + 1:]
    if len(rel) >= 3 and rel[0].endswith(".data"):
        return _SCHEMES.get(rel[1], "unknown"), "/".join(rel[2:])
    return "site", "/".join(rel)


def at_site_root(path: Path) -> bool:
    """Installed directly in site-packages - where Python reads .pth files and sitecustomize at every start."""
    place = installed_place(path)
    return place is not None and place[0] == "site" and "/" not in place[1]


def placed_outside(path: Path) -> bool:
    """Installed outside site-packages (bin, the environment root): it can run without being imported."""
    place = installed_place(path)
    return place is not None and place[0] in ("bin", "prefix", "unknown")


def is_test_path(rs: Ruleset, path: Path) -> bool:
    return bool(rs.test_path.search(str(path)))


def is_dev_path(rs: Ruleset, path: Path, names: set | None = None) -> bool:
    rel = package_relative(path).split("/")
    return len(rel) > 1 and rel[0].lower() in (rs.dev_toplevel if names is None else names)


def install_time_setups(rs: Ruleset, files: list[Path]) -> set[Path]:
    """The setup.py files that actually run on `pip install`. A wheel never runs one; an sdist
    runs only its root setup.py (the shallowest), not the ones nested in tools/ or examples/.
    Found via real false positives: tensorflow's wheel ships tools/pip_package/setup.py and mypy
    ships mypyc/lib-rt/setup.py, both counted as install hooks."""
    setups = [p for p in files if p.name == "setup.py" and p.is_file() and not is_test_path(rs, p)]
    if not setups or any(part.endswith(".whl.unpacked") for part in setups[0].parts):
        return set()
    shallowest = min(len(p.parts) for p in setups)
    return {p for p in setups if len(p.parts) == shallowest}


def line_numbers_matching(lines: list[str], patterns: list[re.Pattern]) -> list[int]:
    return [i for i, line in enumerate(lines) if any(p.search(line) for p in patterns)]


# A chain endpoint that only appears inside a string literal is usually prose, not code: `hol-guard` (a security
# scanner) got BLOCKed because its f-strings "eval(): ..." and "marshal.loads(): ..." sat 4 lines apart.
# What stays a chain: code in a string - both endpoints in the SAME literal, the literal is an argument of
# exec/eval/compile, or the literal itself holds two or more kinds of chain calls (a payload, not prose).
_EXEC_ARG = re.compile(r"(?<![\w.])(?:exec|eval|compile)\s*\(\s*$")
_QUOTE_OR_COMMENT = re.compile(r"[\"'#]")
_PREFIX = re.compile(r"(?<![\w])[rRbBuUfF]{1,2}$")


def _odd_backslashes_before(text: str, idx: int) -> bool:
    k = idx
    while k > 0 and text[k - 1] == "\\":
        k -= 1
    return (idx - k) % 2 == 1


def _close_index(text: str, quote: str, start: int, end: int) -> int:
    """Index just after the first unescaped `quote` in text[start:end], else -1. Linear: every quote found is looked at once."""
    i = start
    while True:
        j = text.find(quote, i, end)
        if j < 0:
            return -1
        k = j
        while k > start and text[k - 1] == "\\":
            k -= 1
        if (j - k) % 2 == 0:                                 # an even run of backslashes does not escape the quote
            return j + len(quote)
        i = j + 1


def string_spans(rs: Ruleset, text: str, every_literal: bool = False) -> list[tuple[int, int]]:
    """[(start, end)] of string literals that hold DATA. Comments, literals passed to exec/eval/compile (their text IS code)
    and literals that themselves hold two or more kinds of chain calls (a self-contained payload) are left out.
    Hand-written linear scanner: a regex version was quadratic on crafted input (5MB of `"\\` never finished). When a
    string does not close on its line the rest of the line is dropped; an unterminated triple quote ends the scan. Both
    leave the remaining text 'outside any literal', i.e. the strict behaviour.
    every_literal: keep those left-out literals too (a chain whose second side must be a command written as a string)."""
    if len(text) > rs.max_literal_scan_bytes:
        return []
    families = rs.payload_families
    spans, pos, n = [], 0, len(text)
    line_end_of: dict[int, int] = {}
    while pos < n:
        m = _QUOTE_OR_COMMENT.search(text, pos)
        if not m:
            break
        i = m.start()
        if text[i] == "#":
            nl = text.find("\n", i)
            pos = n if nl < 0 else nl + 1
            continue
        q = text[i]
        triple = text.startswith(q * 3, i)
        pre = _PREFIX.search(text, max(0, i - 2), i)
        start = pre.start() if pre else i
        if triple:
            end = _close_index(text, q * 3, i + 3, n)
            if end < 0:
                break                                        # unterminated triple quote: stop, the rest counts as outside
        else:
            nl = text.find("\n", i)
            walked = []
            while 0 < nl < n and _odd_backslashes_before(text, nl):      # backslash-newline continues the string
                if nl in line_end_of:                                    # already walked from an earlier start: reuse
                    nl = line_end_of[nl]
                    break
                walked.append(nl)
                nl = text.find("\n", nl + 1)
            for w in walked:                                             # every continued newline is walked once overall
                line_end_of[w] = nl
            line_end = n if nl < 0 else nl
            end = _close_index(text, q, i + 1, line_end)
            if end < 0:
                pos = line_end + 1                           # unterminated on this line: drop the rest of the line
                continue
        pos = end
        if not every_literal:
            if _EXEC_ARG.search(text[max(0, start - 24):start]):
                continue                                     # exec("...") / eval("..."): the text IS code
            body = text[start:end]
            if sum(1 for fam in families if any(p.search(body) for p in fam)) >= 2:
                continue                                     # self-contained payload (dropper), not prose
        spans.append((start, end))
    return spans


def find_chain(rs: Ruleset, lines: list[str], group_a: list[re.Pattern], group_b: list[re.Pattern],
               window: int, text: str | None = None, a_in_strings: bool = False,
               b_in_strings: bool = False) -> tuple[int, int] | None:
    """First (a_line, b_line) pair (0-based) within `window` lines of each other, else None.
    `text` (the same lines joined) lets a file lacking either side be rejected with a few whole-text searches
    instead of a per-line pass - most files in a large package - and enables the string-literal rule above.
    a_in_strings: the first side may sit in a one-line string (a file path such as '~/.ssh/id_rsa' always does);
    it still may not sit in a multi-line docstring, and the second side must be code.
    b_in_strings: the second side must sit in a one-line string and the first side be code - a call that runs a command
    written as a string (`os.system("curl … | sh")`); a message that only mentions the command is not a call."""
    if text is not None and not (any(p.search(text) for p in group_a) and any(p.search(text) for p in group_b)):
        return None
    if text is None:
        a_lines = line_numbers_matching(lines, group_a)
        b_lines = line_numbers_matching(lines, group_b) if a_lines else []
        return next(((a, b) for a in a_lines for b in b_lines if abs(a - b) <= window), None)

    starts = [0]
    for ln in text.split("\n")[:-1]:
        starts.append(starts[-1] + len(ln) + 1)

    def hits(group):
        out = []
        for p in group:
            for m in p.finditer(text):
                out.append((bisect.bisect_right(starts, m.start()) - 1, m.start()))
        return sorted(out)

    a_hits, b_hits = hits(group_a), hits(group_b)
    spans = None
    span_of = lambda pos: next((i for i, (s0, e0) in enumerate(spans) if s0 <= pos < e0), None)  # noqa: E731
    for al, apos in a_hits:
        for bl, bpos in b_hits:
            if abs(al - bl) > window:
                continue
            if spans is None:
                spans = string_spans(rs, text, every_literal=b_in_strings)
            sa, sb = span_of(apos), span_of(bpos)
            if b_in_strings:
                if sa is None and sb is not None and "\n" not in text[spans[sb][0]:spans[sb][1]]:
                    return al, bl
                continue
            if a_in_strings:
                if sb is None and (sa is None or "\n" not in text[spans[sa][0]:spans[sa][1]]):
                    return al, bl
                continue
            if (sa is None and sb is None) or (sa is not None and sa == sb):
                return al, bl
    return None


# --- alias resolution -------------------------------------------------------
# Textual keyword/chain matching is defeated by `from os import system as _s`, `from base64 import b64decode` or
# `_x = exec`. Found on real malware samples (DataDog malicious-software-packages-dataset): colored-fidget, libsock4,
# aeodata, libide. Calls to a tracked module's function through an alias are rewritten to the canonical dotted form
# on a normalized copy (line numbers are preserved, the original text is still what evidence shows). What is
# tracked is listed in signals.json "aliases".
_FROM_IMPORT = re.compile(r"\bfrom\s+([\w.]+)\s+import\s+([\w, ]+)")
_IMPORT_AS = re.compile(r"\bimport\s+([\w.]+)\s+as\s+(\w+)")
_BUILTIN_ASSIGN = re.compile(r"(?<![\w.])(\w+)\s*=\s*(eval|exec)\b(?!\s*\()")
_DEF_OR_IMPORT_LINE = re.compile(r"^\s*(def|class|from|import)\s")


def resolve_aliases(rs: Ruleset, text: str) -> str:
    calls: dict[str, str] = {}    # alias -> canonical dotted callable, used as alias(
    mods: dict[str, str] = {}     # alias -> canonical module, used as alias.attr
    lines = text.split("\n")
    for line in lines:            # cheap substring gates before any regex runs
        if "import" in line:
            for mod, names in _FROM_IMPORT.findall(line):
                for part in names.split(","):
                    m = re.match(r"\s*(\w+)(?:\s+as\s+(\w+))?\s*$", part)
                    if not m:
                        continue
                    orig, alias = m.group(1), m.group(2) or m.group(1)
                    full = f"{mod}.{orig}"
                    if full in rs.alias_modules:
                        mods[alias] = full
                    elif full in rs.alias_call_targets or mod in rs.alias_all_functions_of:
                        calls[alias] = full
                    elif orig in rs.alias_builtins and mod != "builtins":
                        calls[alias] = full        # `from re import compile`: not the builtin
            for mod, alias in _IMPORT_AS.findall(line):
                if mod in rs.alias_modules:
                    mods[alias] = mod
        if "=" in line and ("eval" in line or "exec" in line):
            for alias, builtin in _BUILTIN_ASSIGN.findall(line):
                calls[alias] = builtin
    mods = {a: f for a, f in mods.items() if a != f}
    calls = {a: f for a, f in calls.items() if a != f}
    if not calls and not mods:
        return text
    out = []
    for line in lines:
        if not _DEF_OR_IMPORT_LINE.match(line):
            for a, full in calls.items():
                if a in line:
                    line = re.sub(r"(?<![\w.])" + re.escape(a) + r"(?=\s*\()", full, line)
            for a, full in mods.items():
                if a in line:
                    line = re.sub(r"(?<![\w.])" + re.escape(a) + r"(?=\.)", full, line)
        out.append(line)
    return "\n".join(out)


# ----------------------------------------------------------------------------- evidence

def add_evidence(rs: Ruleset, features, rule: str, path: Path, lines: list[str], idx: int,
                 extra: dict | None = None) -> None:
    """Where in the package a signal fired. Capped per rule so a big package cannot bloat the record. Snippets are
    untrusted package text - length-limited here, escaped again wherever they are displayed."""
    if sum(1 for e in features.evidence if e["rule"] == rule) >= rs.max_evidence:
        return
    item = {"rule": rule, "file": package_relative(path), "line": idx + 1,
            "snippet": lines[idx].strip()[:rs.snippet_max]}
    if extra:
        item.update(extra)
    features.evidence.append(item)


# ----------------------------------------------------------------------------- detectors

def _entropy_of_block(block: str) -> float:
    try:
        return shannon_entropy(base64.b64decode(block, validate=True))
    except Exception:
        return shannon_entropy(block.encode())


def _startup(rs: Ruleset, rule: dict, path: Path, features) -> float:
    """.pth lines Python executes / startup .py: chain -> pth_chain, risky call -> pth_exec, long encoded block -> entropy."""
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return 0.0
    orig_lines = text.splitlines()
    if rule["exec_lines"] == "all":
        exec_lines = list(enumerate(orig_lines))
    else:
        pats = rs.sig(rule["exec_lines"])
        exec_lines = [(i, l) for i, l in enumerate(orig_lines) if any(p.search(l) for p in pats)]
    ids, sets = rule["evidence_ids"], rule.get("sets", {})
    idxs = [i for i, _ in exec_lines]
    joined = resolve_aliases(rs, "\n".join(orig_lines[i] if i in idxs else "" for i in range(len(orig_lines))))
    nlines = joined.splitlines()
    chain = None
    for first, then in rule["chains"]:
        chain = find_chain(rs, nlines, rs.sig(first), rs.sig(then), int(rule["within_lines"]), joined)
        if chain:
            break
    if chain:
        for f in sets.get("chain", []):
            setattr(features, f, True)
        add_evidence(rs, features, ids["chain"], path, orig_lines, chain[0],
                     {"pair_line": chain[1] + 1, "pair_snippet": orig_lines[chain[1]].strip()[:rs.snippet_max]})
    else:
        risky = rs.sig(rule["risky"])
        for i in idxs:
            if any(p.search(nlines[i]) for p in risky):
                for f in sets.get("risky", []):
                    setattr(features, f, True)
                add_evidence(rs, features, ids["risky"], path, orig_lines, i)
                break
    best = 0.0
    ent = rule["entropy"]
    blocks = rs.sig(ent["signal"])
    for i in idxs:
        for p in blocks:
            for m in p.finditer(orig_lines[i]):
                e = _entropy_of_block(m.group(0))
                if e > float(ent["min_entropy"]):
                    add_evidence(rs, features, ids["entropy"], path, orig_lines, i, {"entropy": round(e, 3)})
                best = max(best, e)
    return best


class _Scan:
    """Per-package state the detectors share (what static_analysis used to keep in locals)."""

    def __init__(self, rs: Ruleset, files: list[Path]):
        self.rs = rs
        self.install_setups = install_time_setups(rs, files)
        self.per_file_keywords: dict[Path, int] = {}
        self.keyword_hits: dict[str, int] = {}
        self.max_entropy = 0.0
        self.keyword_patterns = {}
        self._lower = (None, "")                         # (text, text.lower()) of the file being checked

    def lower(self, text: str) -> str:
        """text.lower(), computed once per file even when several rules check it (one _Scan per scan: no sharing)."""
        if self._lower[0] is not text:
            self._lower = (text, text.lower())
        return self._lower[1]


def _keyword_count(st: _Scan, rule: dict, path: Path, text: str, norm_text: str, lines: list[str],
                   orig_lines: list[str], features) -> None:
    rs = st.rs
    lits = rs.keyword_literals[rule["signal"]]
    pats = rs.sig(rule["signal"])
    for kw, pat in zip(lits, pats):
        if kw not in norm_text:        # plain substring test first: regex over every file dominated the scan time
            continue
        n = len(pat.findall(norm_text))
        if n:
            st.keyword_hits[kw] = st.keyword_hits.get(kw, 0) + n
            st.per_file_keywords[path] = st.per_file_keywords.get(path, 0) + n
            if path in st.install_setups:
                features.setup_keyword_total += n
            for idx, line in enumerate(lines):
                if pat.search(line):
                    add_evidence(rs, features, evidence_id(rule), path, orig_lines, idx, {"pattern": kw})
                    break


def _chain(st: _Scan, rule: dict, path: Path, text: str, norm_text: str, lines: list[str],
           orig_lines: list[str], features) -> None:
    rs = st.rs
    low = st.lower(norm_text)
    if not (rs.may_match(rule["first"], norm_text, low) and rs.may_match(rule["then"], norm_text, low)):
        return
    if rule.get("max_line_chars"):       # minified code is one long line: "near each other" says nothing there
        n = int(rule["max_line_chars"])
        lines = [l if len(l) <= n else "" for l in lines]
        norm_text = "\n".join(lines)
    chain = find_chain(rs, lines, rs.sig(rule["first"]), rs.sig(rule["then"]), int(rule["within_lines"]), norm_text,
                       a_in_strings=bool(rule.get("first_in_strings")), b_in_strings=bool(rule.get("then_in_strings")))
    if chain:
        for f in rule.get("sets", []):
            setattr(features, f, True)
        add_evidence(rs, features, evidence_id(rule), path, orig_lines, chain[0],
                     {"pair_line": chain[1] + 1, "pair_snippet": orig_lines[chain[1]].strip()[:rs.snippet_max]})


def _entropy_blocks(st: _Scan, rule: dict, path: Path, text: str, norm_text: str, lines: list[str],
                    orig_lines: list[str], features) -> None:
    rs = st.rs
    pats = rs.sig(rule["signal"])
    # one whole-text pass first; the per-line pass (needed for the evidence line number) only runs for files that
    # have a long block
    if not any(p.search(text) for p in pats):
        return
    for idx, line in enumerate(orig_lines):
        for p in pats:
            for m in p.finditer(line):
                block = m.group(0)
                if rule.get("skip_url_tokens"):
                    start = line.rfind(" ", 0, m.start()) + 1
                    end = line.find(" ", m.end())
                    if "://" in line[start:end if end != -1 else len(line)]:
                        continue        # a long URL/path is not an encoded payload
                e = _entropy_of_block(block)
                if e > float(rule["min_entropy"]):
                    add_evidence(rs, features, evidence_id(rule), path, orig_lines, idx, {"entropy": round(e, 3)})
                st.max_entropy = max(st.max_entropy, e)


def _docstring_spans(rs: Ruleset, text: str) -> list[tuple[int, int]]:
    """Multi-line triple-quoted literals (docstrings, usage examples): prose, not code that runs."""
    out = []
    for a, b in string_spans(rs, text):
        body = text[a:b].lstrip("rRbBuUfF")
        if body[:3] in ('"""', "'''") and "\n" in body:
            out.append((a, b))
    return out


def _first_line(st: _Scan, rule: dict, path: Path, text: str, norm_text: str, lines: list[str],
                orig_lines: list[str], features) -> None:
    rs = st.rs
    pats = rs.sig(rule["signal"])
    if rule.get("skip_docstrings"):                      # only with text "original": offsets are into `text`
        if not rs.may_match(rule["signal"], text, st.lower(text)):
            return
        hits = sorted(m.start() for p in pats for m in p.finditer(text))
        if not hits:
            return
        skip = _docstring_spans(rs, text)
        pos = next((h for h in hits if not any(a <= h < b for a, b in skip)), None)
        if pos is None:
            return
        offsets = [0]
        for l in text.splitlines(True):
            offsets.append(offsets[-1] + len(l))
        idx = bisect.bisect_right(offsets, pos) - 1
        for f in rule.get("sets", []):
            setattr(features, f, True)
        add_evidence(rs, features, evidence_id(rule), path, orig_lines, idx)
        return
    target = text if rule.get("text") == "original" else norm_text
    if not rs.may_match(rule["signal"], target, st.lower(target)):
        return
    low = rule["signal"] in rs.lowercase
    near = rule.get("unless_near")              # a hit with this signal within N lines is talk ABOUT the thing, not it
    seen = orig_lines if rule.get("text") == "original" else lines
    for idx, line in enumerate(seen):
        if any(p.search(line.lower() if low else line) for p in pats):
            if near and _near(rs, near, seen, idx):
                continue
            for f in rule.get("sets", []):
                setattr(features, f, True)
            add_evidence(rs, features, evidence_id(rule), path, orig_lines, idx)
            break


def _near(rs: Ruleset, near: dict, lines: list[str], idx: int) -> bool:
    n = int(near.get("lines", 2))
    low = near["signal"] in rs.lowercase
    block = lines[max(0, idx - n):idx + n + 1]
    return any(p.search(l.lower() if low else l) for l in block for p in rs.sig(near["signal"]))


def _setup_local_imports(st: _Scan, rule: dict, features) -> None:
    """Dangerous keywords in the package's own modules that setup.py imports. An install hook such as
    `from main import main; main()` runs them at install time, so the calls living in main.py belong to the hook. Only
    single-file modules next to setup.py count: matching whole packages made `import numpy` inside numpy's own
    setup.py pull in the entire library (measured: 4 extra popular packages flagged)."""
    rs = st.rs
    imp = rs.sig(rule["signal"])
    kw_pats = rs.sig(rule["keywords"])
    for setup in st.install_setups:
        try:
            src = setup.read_text(errors="ignore")
        except OSError:
            continue
        names = set()
        for p in imp:
            names |= {a or b for a, b in p.findall(src)}
        total, hit = 0, []
        for name in names:
            cand = setup.parent / f"{name}.py"
            n = st.per_file_keywords.get(cand, 0)
            if n:
                total += n
                hit.append(cand)
        if total:
            features.setup_import_keyword_total += total
            lines_of = hit[0].read_text(errors="ignore").splitlines()
            idx = next((i for i, l in enumerate(resolve_aliases(rs, hit[0].read_text(errors="ignore")).splitlines())
                        if any(pt.search(l) for pt in kw_pats)), 0)
            add_evidence(rs, features, evidence_id(rule), hit[0], lines_of, idx)


def _placement(rs: Ruleset, rule: dict, files: list[Path], features) -> None:
    """Checks on where files land when installed (installed_place), not on what they contain:
      command_shadowing    a command the package installs (entry_points.txt console/gui scripts, <dist>.data/scripts)
                           named like a common command (signals.json "commands"), unless named after the package itself
      sourceless_bytecode  a module shipped as .pyc only (the extraction keeps an empty marker: the code cannot be read)
      environment_index    a pip/uv config placed into the environment root that sends installs elsewhere"""
    check = rule["check"]
    dist = _dist_of(files) if check == "command_shadowing" else ""
    for path in files:
        place = installed_place(path)
        if place is None:
            continue
        kind, rel = place
        if check == "command_shadowing":
            if kind == "bin" and "/" not in rel:
                names = [(rel, [f"bin/{rel}"], 0)]
            elif kind == "site" and rel.endswith(".dist-info/entry_points.txt"):
                lines = text_lines_of(path)
                names = [(name, lines, idx) for name, idx, _ in _entry_point_commands(path)]
            else:
                names = []
            for name, lines, idx in names:
                low = name.lower()
                if low in rs.common_commands and not (dist and low.startswith(dist)):    # pip -> pip3 is its own
                    add_evidence(rs, features, evidence_id(rule), path, lines, idx)
        elif check == "sourceless_bytecode":
            if path.suffix == ".pyc" and kind == "site" and "__pycache__" not in rel and not path.with_suffix(".py").exists():
                add_evidence(rs, features, evidence_id(rule), path, [f"{rel} (.pyc without source)"], 0)
        elif check == "environment_index":
            if kind == "prefix" and rel in rule.get("files", []):
                import index_config
                try:
                    found = index_config._pip_text(path.read_text(errors="replace"), rel) if rel.startswith("pip") else \
                        index_config._uv_settings(index_config._toml_text(path.read_text(errors="replace")), rel)
                except Exception:
                    found = [("custom_index", rel, "unreadable")]
                if found:
                    add_evidence(rs, features, evidence_id(rule), path, [found[0][1]], 0)


def _dist_of(files: list[Path]) -> str:
    """The distribution name of a wheel, normalised, or "": from its <dist>-<ver>.dist-info or <dist>-<ver>.data folder,
    else the wheel file name (<dist>-<ver>-<tags>.whl) - the extraction may keep nothing from .dist-info."""
    for p in files:
        for part in p.parts:
            for suffix in (".dist-info", ".data"):
                if part.endswith(suffix):
                    return re.sub(r"[-_.]+", "-", part[:-len(suffix)].rsplit("-", 1)[0]).lower()
    for p in files:
        for part in p.parts:
            if part.endswith(".whl.unpacked"):
                return re.sub(r"[-_.]+", "-", part.split("-", 1)[0]).lower()
    return ""


def _entry_point_commands(path: Path) -> list[tuple[str, int, str]]:
    """(command, line index, line) of the console/gui scripts an entry_points.txt declares."""
    out, section = [], ""
    for idx, line in enumerate(text_lines_of(path)):
        s = line.strip()
        if s.startswith("["):
            section = s.strip("[]").strip()
        elif section in ("console_scripts", "gui_scripts") and "=" in s:
            out.append((s.split("=", 1)[0].strip(), idx, s))
    return out


_PER_FILE = {"keyword_count": _keyword_count, "chain": _chain, "entropy_blocks": _entropy_blocks, "first_line": _first_line}


def _text_file_rules(rs: Ruleset, st: _Scan, rules: list[dict], path: Path, features, skip_test_and_dev: bool = True,
                     dev_names: set | None = None) -> None:
    """Rules with files "text": any text file the package ships (.js, .md, METADATA, ...), read as it is. Text that
    talks to an AI agent can sit anywhere, not only in Python code. Test and maintenance folders are left out."""
    name = path.name.lower()
    if path.suffix.lower() not in rs.text_suffixes and name not in rs.text_names:
        return
    if skip_test_and_dev and (is_test_path(rs, path) or is_dev_path(rs, path, dev_names)):
        return
    try:
        if path.stat().st_size > rs.text_max_bytes:
            return
        text = path.read_text(errors="ignore")
    except OSError:
        return
    lines, lower = None, text.lower()
    for rule in rules:
        target = lower if rule["signal"] in rs.lowercase else text
        if not rs.may_match(rule["signal"], text, lower) or not any(p.search(target) for p in rs.sig(rule["signal"])):
            continue                                     # one pass over the whole file instead of one per line
        lines = lines if lines is not None else text.splitlines()
        _PER_FILE[rule["detector"]](st, rule, path, text, text, lines, lines, features)


def run_static(rs: Ruleset, files: list[Path], features, ecosystem: str | None = None) -> None:
    """Apply rules.json to the unpacked files, filling `features` (scan_engine.ScanFeatures) as static_analysis did.
    ecosystem: which kind of thing is scanned (signals.json "ecosystems"; default the features' own, else pypi) - it
    decides which languages are read as code. A PyPI scan reads exactly what it did before languages existed."""
    eco = rs.ecosystems.get(ecosystem or getattr(features, "ecosystem", None) or "pypi")
    if eco is None:
        raise RulesetError(f"unknown ecosystem '{ecosystem or getattr(features, 'ecosystem', None)}'")
    code_langs, skip_td, dev_names = eco["code"], eco["skip_test_and_dev"], eco["dev_names"]
    st = _Scan(rs, files)
    py_count = py_loc = total_count = 0
    chain_flags = {f for r in rs.rules if r["detector"] == "chain" for f in r.get("sets", [])}
    for f in chain_flags:                                # these were locals that overwrote the feature at the end
        setattr(features, f, False)
    file_rules = [r for r in rs.rules if r["detector"] not in ("setup_local_imports", "placement") and r.get("files") != "text"]
    text_rules = [r for r in rs.rules if r.get("files") == "text"]

    real_lines: dict = {}                                # path -> its real lines, for files read through code_view
    for path in files:
        if not path.is_file():
            continue
        total_count += 1
        ev_before = len(features.evidence)
        is_py = path.suffix == ".py"
        lang = lang_of(rs, path)
        # a file installed outside the package (a command in bin, a file in the environment root) is code in any language
        is_code = lang in code_langs or (lang is not None and placed_outside(path))
        loaded = None                                    # (text, norm_text, lines, orig_lines, is_test) once read
        read_failed = False
        for rule in file_rules:
            det = rule["detector"]
            if det == "startup":
                site_root = archive_depth(path) == 1 or at_site_root(path)    # incl. <dist>.data/purelib|platlib/
                if rule["select"] == "pth":
                    selected = path.suffix == ".pth" and site_root
                else:                                     # startup_py: sitecustomize/usercustomize at the wheel root
                    selected = is_py and path.name in rs.startup_py and site_root
                if selected:
                    e = _startup(rs, rule, path, features)
                    if rule.get("counts_to_max_entropy"):
                        st.max_entropy = max(st.max_entropy, e)
                continue
            if not is_code or read_failed or lang not in rs.rule_langs[rule["id"]]:
                continue
            if loaded is None:
                is_test = skip_td and (is_test_path(rs, path) or is_dev_path(rs, path, dev_names))
                try:
                    text = path.read_text(errors="ignore")
                except Exception:
                    read_failed = True
                    continue
                orig_lines = text.splitlines()
                view = code_view(rs, lang, orig_lines)
                if view is not None:                      # comments and printed messages blanked (js, shell)
                    text = "\n".join(view)
                    orig_lines = view
                    real_lines[path] = text_lines_of(path)
                norm_text = resolve_aliases(rs, text) if lang == "python" else text
                loaded = (text, norm_text, norm_text.splitlines(), orig_lines, is_test)
                if not is_test and is_py:
                    py_loc += len(orig_lines)
            text, norm_text, lines, orig_lines, is_test = loaded
            scope = rule.get("files", "code")
            if is_test:
                continue
            if scope == "install_setup" and path not in st.install_setups:
                continue
            _PER_FILE[det](st, rule, path, text, norm_text, lines, orig_lines, features)
        if path in real_lines:                           # evidence snippets show the real line, not the blanked view
            real = real_lines.pop(path)
            for e in features.evidence[ev_before:]:
                for key, ln in (("snippet", e.get("line")), ("pair_snippet", e.get("pair_line"))):
                    if key in e and ln and 0 < ln <= len(real):
                        e[key] = real[ln - 1].strip()[:rs.snippet_max]
        if text_rules and not read_failed:
            _text_file_rules(rs, st, text_rules, path, features, skip_td, dev_names)
        if is_py:
            py_count += 1
        if read_failed:                                  # the old loop `continue`d here, skipping the README check
            continue
        if path.name.lower() == "readme" or path.name.lower().startswith("readme."):
            features.has_readme = True

    for rule in rs.rules:
        if rule["detector"] == "setup_local_imports":
            _setup_local_imports(st, rule, features)
        elif rule["detector"] == "placement":
            _placement(rs, rule, [p for p in files if p.is_file()], features)

    features.file_count = total_count
    features.py_file_count = py_count
    features.py_loc = py_loc
    features.keyword_hits = st.keyword_hits
    features.keyword_total = sum(st.keyword_hits.values())
    features.max_entropy = round(st.max_entropy, 3)


# ----------------------------------------------------------------------------- scoring

def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
        prev = cur
    return prev[-1]


def typosquat(rs: Ruleset, name: str, features) -> None:
    best = None
    best_dist = None
    for pop in rs.sub["typosquat"]["popular_names"]:
        d = levenshtein(name.lower(), pop.lower())
        if best_dist is None or d < best_dist:
            best_dist = d
            best = pop
    features.min_edit_distance = best_dist
    features.closest_popular_name = best


def _cond(c: dict, features) -> bool:
    if "all" in c:
        return all(_cond(x, features) for x in c["all"])
    if "any" in c:
        return any(_cond(x, features) for x in c["any"])
    if "evidence" in c:                                  # a rule of rules.json left evidence (new rules need no new field)
        return any(e.get("rule") == c["evidence"] for e in features.evidence)
    v = getattr(features, c["field"], None)              # a field no scan sets (a module's typo) is never true
    if "equals" in c:
        return v == c["equals"]
    return bool(v)


def _reason(rs: Ruleset, h: dict, features) -> str:
    vals = {}
    if h.get("window_from"):
        vals["window"] = rs.window_of(h["window_from"])
    if features.skipped_members:
        name, why = features.skipped_members[0]
        vals.update(skipped_count=len(features.skipped_members), skipped_example=repr(name[:50]), skipped_why=why)
    for k, spec in h.get("vars", {}).items():
        if "if" in spec:
            vals[k] = spec["then"] if getattr(features, spec["if"], None) else spec["else"]
        elif "join" in spec:
            vals[k] = spec.get("sep", " / ").join(label for field, label in spec["join"] if getattr(features, field, None))
        elif "join_evidence" in spec:              # "action": only evidence the behavior policy gave that action
            got = {e.get("rule") for e in features.evidence if "action" not in spec or e.get("action") == spec["action"]}
            vals[k] = spec.get("sep", " / ").join(label for rule, label in spec["join_evidence"] if rule in got)
    return h["reason"].format_map(_Missing(vals))       # a name the reason text uses but nothing fills shows as "?"


class _Missing(dict):
    def __missing__(self, key):
        return "?"


def _typosquat_sub(rs: Ruleset, features, reasons: list) -> float:
    t = rs.sub["typosquat"]
    max_dist = int(t["max_distance_short"]) if len(features.name) <= int(t["short_name_len"]) else int(t["max_distance"])
    if features.min_edit_distance is not None and 0 < features.min_edit_distance <= max_dist:
        reasons.append(t["reason"].format(closest_popular_name=features.closest_popular_name,
                                          min_edit_distance=features.min_edit_distance))
        return 1.0
    return 0.0


def _vuln_sub(rs: Ruleset, features, reasons: list) -> float:
    if features.osv_vulns:
        reasons.append(rs.sub["vuln"]["reason"].format(n_vulns=len(features.osv_vulns),
                                                       osv_max_severity=features.osv_max_severity))
        return 1.0
    return 0.0


def _classify(rs: Ruleset, total: float) -> str:
    if total >= rs.block_threshold:
        return "BLOCK"
    if total >= rs.review_threshold:
        return "NEEDS_HUMAN_REVIEW"
    return "ALLOW"


def _apply_hard_rules(rs: Ruleset, mode: str, features, total: float, reasons: list):
    """Returns (verdict, score, reasons) if a BLOCK rule fired, else (None, total, reasons) with review floors applied."""
    for h in rs.hard_rules:
        if mode not in h.get("modes", ["rules", "ml"]) or not _cond(h["when"], features):
            continue
        if h["action"] == "block":
            score = total if h.get("score") == "total" else max(total, rs.block_threshold)
            return "BLOCK", round(score, 3), reasons + [_reason(rs, h, features)]
        total = max(total, rs.review_floor)
        reasons.append(_reason(rs, h, features))
    return None, total, reasons


def score_rules(rs: Ruleset, features) -> tuple[str, float, list]:
    """Weighted sub-scores, then hard rules, then thresholds (the path used when ML gave no result)."""
    reasons, sub = [], {}
    sub["vuln"] = _vuln_sub(rs, features, reasons)

    e = rs.sub["entropy"]
    sub["entropy"] = min(1.0, features.max_entropy / float(e["divisor"]))
    if features.max_entropy > float(e["reason_above"]):
        reasons.append(e["reason"].format(max_entropy=features.max_entropy))

    # denominator scales with package size (non-test lines of code / 100, i.e. roughly "two hits per average file")
    # so a handful of legitimate keyword hits in a large codebase doesn't read as high risk, while a tiny file with
    # the same count does. Floor of 3 avoids a one-file package dividing by ~1.
    k = rs.sub["keyword"]
    denom = max(int(k["min_denominator"]), features.py_loc // int(k["loc_per_unit"]))
    sub["keyword"] = min(1.0, features.keyword_total / denom)
    if features.keyword_total > 0:
        reasons.append(k["reason"].format(keyword_total=features.keyword_total, denominator=denom,
                                          keyword_hits=features.keyword_hits))

    sub["install_hook"] = 1.0 if features.has_install_hook else 0.0
    if features.has_install_hook:
        reasons.append(rs.sub["install_hook"]["reason"])

    sub["typosquat"] = _typosquat_sub(rs, features, reasons)

    r = rs.sub["reputation"]
    risk = 0.0
    if features.package_age_days is not None and features.package_age_days < float(r["new_days"]):
        risk += float(r["new_points"])
        reasons.append(r["reason_new"].format(package_age_days=features.package_age_days))
    if not features.has_readme:
        risk += float(r["no_readme_points"])
    if features.maintainer_count == 0:
        risk += float(r["no_maintainer_points"])
    sub["reputation"] = min(1.0, risk)

    total = sum(rs.weights[k] * sub[k] for k in rs.weights)
    verdict, score, reasons = _apply_hard_rules(rs, "rules", features, total, reasons)
    if verdict:
        return verdict, score, reasons
    total = score

    # [ML] this path runs when ML gave no usable result; an alert can only raise to REVIEW, never BLOCK
    ml = features.ml
    if ml and ml.get("ok"):
        if ml.get("alert"):
            total = max(total, rs.review_floor)
            why = " / ".join(t["desc"] for t in ml.get("reasons", [])[:3]) or "statistical anomaly pattern"
            reasons.append(f"[ML] anomaly alert (ml_score={ml['ml_score']:.3f}, threshold {ml['threshold']:.3f}): {why}")
        elif ml.get("notes"):
            reasons.append("[ML note] score below threshold, but has install-time behavior: "
                           + " / ".join(t["desc"] for t in ml["notes"]))
    elif ml and not ml.get("disabled"):
        reasons.append(f"[ML] no verdict ({ml.get('error')})")
    if ml and ml.get("ok") and not ml.get("code_analyzed") and "ArchiveLimitError" in str(ml.get("code_source")):
        total = max(total, rs.review_floor)
        reasons.append("[ML] could not read the code: archive over the size limit (possible zip bomb) → needs at least review")

    return _classify(rs, total), round(total, 3), reasons


def ml_subscore(rs: Ruleset, ml_score: float, threshold: float) -> float:
    """ML score -> 0..1, scaled so the ML alert threshold lands exactly on the review threshold. On its own the ML
    score reaches at most ml weight, which is below the block threshold, so it never blocks."""
    anchor = min(1.0, (rs.review_threshold + 0.001) / rs.ml_weight)
    if threshold <= 0 or threshold >= 1:
        return min(1.0, max(0.0, ml_score))
    if ml_score < threshold:
        return anchor * ml_score / threshold
    return anchor + (1 - anchor) * (ml_score - threshold) / (1 - threshold)


def score_ml(rs: Ruleset, features) -> tuple[str, float, list]:
    """The path used when the ML model returned a score: vuln + typosquat + ML, then the hard rules marked for ml mode."""
    ml = features.ml
    reasons, sub = [], {}
    sub["vuln"] = _vuln_sub(rs, features, reasons)
    sub["typosquat"] = _typosquat_sub(rs, features, reasons)
    sub["ml"] = ml_subscore(rs, ml["ml_score"], ml["threshold"])
    if ml.get("alert"):
        why = " / ".join(t["desc"] for t in ml.get("reasons", [])[:3]) or "statistical anomaly pattern"
        reasons.append(f"[ML] anomaly alert (ml_score={ml['ml_score']:.3f}, threshold {ml['threshold']:.3f}): {why}")
    elif ml.get("notes"):
        reasons.append("[ML note] score below threshold, but has install-time behavior: "
                       + " / ".join(t["desc"] for t in ml["notes"]))
    total = sum(rs.weights[k] * sub[k] for k in rs.ml_subscores) + rs.ml_weight * sub["ml"]
    verdict, score, reasons = _apply_hard_rules(rs, "ml", features, total, reasons)
    if verdict:
        return verdict, score, reasons
    return _classify(rs, score), round(score, 3), reasons
