"""Rule modules on top of the base rules (guard/rule_modules.py): a person adds, replaces, tunes or switches
off rules in ~/.aasm/rules/*.json without editing guard/rules; a broken module is skipped, never breaks the guard.
run: python3 tests/test_rule_modules.py"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "guard"
sys.path.insert(0, str(GUARD))
import rule_engine  # noqa: E402
import rule_modules  # noqa: E402
import scan_engine as se  # noqa: E402
import switches  # noqa: E402

MARKER = {"description": "company secret marker", "regex": ["CORP-SECRET-[0-9]{4}"], "quick": ["corp-secret-"]}
MARKER_RULE = {"id": "corp_secret_marker", "title": "Company secret marker in the code", "detector": "first_line",
               "signal": "corp_marker", "text": "original", "files": "code",
               "report": {"label": "company secret marker", "path": "inside the package code", "risk": "package mixed with company secrets",
                          "reason": "company secret marker string", "benign": "internal package"}}
MARKER_HARD = {"id": "corp_secret_marker", "when": {"evidence": "corp_secret_marker"}, "action": "review",
               "reason": "[user rule] company secret marker → review", "modes": ["rules", "ml"]}


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


class Modules(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.dir = self.home / ".aasm" / "rules"
        self.dir.mkdir(parents=True)
        self.env = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        self.env.start()
        os.environ.pop("AASM_RULE_MODULES", None)
        self.sysdir = mock.patch.object(rule_modules, "SYSTEM_DIR", self.home / "no-admin")
        self.sysdir.start()

    def tearDown(self):
        self.env.stop()
        self.sysdir.stop()

    def module(self, name, doc):
        (self.dir / f"{name}.json").write_text(json.dumps(doc, ensure_ascii=False) if not isinstance(doc, str) else doc)

    def load(self):
        return rule_engine.load(modules=True)

    def test_no_modules_is_the_base(self):
        rs, base = self.load(), rule_engine.load()
        self.assertEqual(rs.modules, [])
        self.assertEqual([r["id"] for r in rs.rules], [r["id"] for r in base.rules])

    def test_add_signal_rule_and_hard_rule(self):
        self.module("corp", {"schema": 1, "name": "company marker", "signals": {"corp_marker": MARKER},
                             "rules": [MARKER_RULE], "hard_rules": [MARKER_HARD]})
        rs = self.load()
        self.assertEqual(rs.modules[0]["status"], "applied", rs.modules)
        files = package({"pkg/__init__.py": "TOKEN = 'CORP-SECRET-1234'\n"})
        f, v = scan(rs, files)
        self.assertIn("corp_secret_marker", {e["rule"] for e in f.evidence})
        self.assertEqual(v.verdict, "NEEDS_HUMAN_REVIEW")
        self.assertTrue(any("user rule" in r for r in v.reasons))
        _, v2 = scan(rule_engine.load(), files)                 # the base rules alone do not know the marker
        self.assertEqual(v2.verdict, "ALLOW")

    def test_tune_base_values(self):
        self.module("tune", {"schema": 1, "add": {"scoring.subscores.typosquat.popular_names": ["langchain"]},
                             "set": {"scoring.thresholds.review": 0.2}})
        rs = self.load()
        self.assertEqual(rs.modules[0]["status"], "applied", rs.modules)
        self.assertEqual(rs.review_threshold, 0.2)
        f, _ = scan(rs, package({"pkg/__init__.py": "x = 1\n"}), name="langchian")
        self.assertEqual(f.closest_popular_name, "langchain")

    def test_replace_and_disable_base(self):
        self.module("off", {"schema": 1, "disable": {"rules": ["agent_prompt_injection"],
                                                    "hard_rules": ["agent_prompt_injection"]}})
        rs = self.load()
        self.assertEqual(rs.modules[0]["status"], "applied", rs.modules)
        self.assertNotIn("agent_prompt_injection", [r["id"] for r in rs.rules])
        self.assertNotIn("agent_prompt_injection", [h["id"] for h in rs.hard_rules])
        self.module("tighter", {"schema": 1, "hard_rules": [dict(MARKER_HARD, id="exfil_signal", action="block",
                                                                when={"evidence": "exfil_endpoint"})]})
        rs = self.load()
        h = next(x for x in rs.hard_rules if x["id"] == "exfil_signal")
        self.assertEqual(h["action"], "block")
        self.assertEqual([x["id"] for x in rs.hard_rules].count("exfil_signal"), 1)   # replaced in place, not added

    def test_behavior_policy(self):
        self.module("beacon", {"schema": 1, "findings": {"sysinfo_beacon": {"call": "review"}}})
        rs = self.load()
        self.assertEqual(rs.modules[0]["status"], "applied", rs.modules)
        from behavior.values import Policy
        self.assertEqual(Policy(doc=rs.raw["behavior"]).action("sysinfo_beacon", "call"), "review")
        self.assertIsNone(Policy().action("sysinfo_beacon", "call"))   # the base file is unchanged

    def test_broken_modules_are_skipped(self):
        self.module("a_bad_json", "{not json")
        self.module("b_unknown_key", {"schema": 1, "rule": []})
        self.module("c_bad_regex", {"schema": 1, "signals": {"corp_marker": {"regex": ["(unclosed"]}}})
        self.module("d_no_such_id", {"schema": 1, "disable": {"rules": ["no_such_rule"]}})
        self.module("e_no_such_finding", {"schema": 1, "findings": {"invented": {"auto": "block"}}})
        self.module("f_bad_action", {"schema": 1, "findings": {"hidden_call": {"auto": "deny"}}})
        self.module("g_bad_path", {"schema": 1, "set": {"scoring.nothing.here": 1}})
        self.module("z_good", {"schema": 1, "signals": {"corp_marker": MARKER}, "rules": [MARKER_RULE]})
        rs = self.load()
        status = {Path(m["file"]).stem: m["status"] for m in rs.modules}
        self.assertEqual(status.pop("z_good"), "applied", rs.modules)
        self.assertEqual(set(status.values()), {"skipped"}, rs.modules)
        self.assertTrue(all(m.get("error") for m in rs.modules if m["status"] == "skipped"))
        self.assertIn("corp_secret_marker", [r["id"] for r in rs.rules])

    def test_typo_in_a_hard_rule_never_crashes_a_verdict(self):
        self.module("typo", {"schema": 1, "hard_rules": [{"id": "typo", "when": {"field": "no_such_field"}, "action": "block",
                                                          "reason": "{no_such_var}"},
                                                         {"id": "typo2", "when": {"field": "has_install_hook"},
                                                          "action": "review", "reason": "hook {no_such_var}"}]})
        rs = self.load()
        f = se.ScanFeatures(name="x", version="1.0")
        f.has_install_hook = True
        verdict, _, reasons = rule_engine.score_rules(rs, f)
        self.assertEqual(verdict, "NEEDS_HUMAN_REVIEW")
        self.assertIn("hook ?", reasons)

    def test_switched_off_and_system_install(self):
        self.module("corp", {"schema": 1, "signals": {"corp_marker": MARKER}, "rules": [MARKER_RULE]})
        with mock.patch.dict(os.environ, {"AASM_RULE_MODULES": "0"}):    # development checkout: the environment works
            self.assertEqual(self.load().modules, [])
        ro = Path(tempfile.mkdtemp())
        os.chmod(ro, 0o555)
        try:
            with mock.patch.object(switches, "GUARD_DIR", ro):            # a guard the user cannot write: admin only
                self.assertEqual(self.load().modules, [])
        finally:
            os.chmod(ro, 0o755)

    def test_admin_folder_must_be_root_owned(self):
        admin = self.home / "etc-aasm-rules"
        admin.mkdir()
        (admin / "a.json").write_text(json.dumps({"schema": 1, "signals": {"corp_marker": MARKER}}))
        with mock.patch.object(rule_modules, "SYSTEM_DIR", admin):
            rs = self.load()
        self.assertEqual([(m["origin"], m["status"]) for m in rs.modules], [("admin", "skipped")])


class Tools(unittest.TestCase):
    def test_rule_check_runs_module_examples_and_verify_lists_modules(self):
        with tempfile.TemporaryDirectory() as t:
            home = Path(t)
            d = home / ".aasm" / "rules"
            d.mkdir(parents=True)
            examples = {"static": {"corp_secret_marker": [
                {"expect": "hit", "why": "marker", "files": {"pkg/a.py": "k = 'CORP-SECRET-0001'\n"}},
                {"expect": "miss", "why": "other text", "files": {"pkg/a.py": "k = 'CORP-PUBLIC'\n"}}]}}
            (d / "corp.json").write_text(json.dumps({"schema": 1, "name": "company marker", "signals": {"corp_marker": MARKER},
                                                     "rules": [MARKER_RULE], "examples": examples}, ensure_ascii=False))
            (d / "broken.json").write_text("{")
            env = {**os.environ, "HOME": str(home)}
            env.pop("AASM_RULE_MODULES", None)
            r = subprocess.run([sys.executable, "-I", str(GUARD / "rule_check.py"), "--modules"], capture_output=True,
                               text=True, env=env)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)           # the broken module is a problem
            self.assertIn("applied: company marker", r.stdout)
            self.assertIn("broken.json", r.stdout)
            self.assertNotIn("corp_secret_marker #", r.stdout)               # both examples met
            (d / "broken.json").unlink()
            r = subprocess.run([sys.executable, "-I", str(GUARD / "rule_check.py"), "--modules"], capture_output=True,
                               text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            r = subprocess.run([sys.executable, "-I", str(GUARD / "rule_check.py")], capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)           # the base check ignores modules
            r = subprocess.run([sys.executable, "-I", str(GUARD / "guard_cli.py"), "verify"], capture_output=True,
                               text=True, env=env)
            self.assertIn("Rule modules: 1 applied", r.stdout, r.stdout + r.stderr)


class AgentWrites(unittest.TestCase):
    def test_agent_writing_a_module_is_stopped(self):
        """~/.aasm/ is a protected path: a rule module written by an agent goes through the same card as the guard's own
        files (in auto mode: a refusal with evidence and an ack id)."""
        with tempfile.TemporaryDirectory() as t:
            home = Path(t) / "home"
            home.mkdir()
            env = {**os.environ, "HOME": str(home), "AASM_MODE": "user"}
            target = home / ".aasm" / "rules" / "off.json"
            for tool, inp in (("Bash", {"command": f"mkdir -p ~/.aasm/rules && echo '{{}}' > {target}"}),
                              ("Write", {"file_path": str(target), "content": "{\"schema\": 1}"})):
                hook = "pretooluse_check.py" if tool == "Bash" else "pretooluse_editwrite_check.py"
                ev = json.dumps({"tool_name": tool, "cwd": t, "tool_input": inp})
                p = subprocess.run([sys.executable, "-I", str(GUARD / "hooks" / hook)], input=ev, capture_output=True,
                                   text=True, env=env)
                out = json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] if p.stdout.strip() else None
                self.assertIn(out, ("ask", "deny"), (tool, p.stdout + p.stderr))


if __name__ == "__main__":
    unittest.main()
