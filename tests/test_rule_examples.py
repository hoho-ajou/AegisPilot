"""Every rule's examples (guard/rules/examples/) hold, every rule has them, and RULES.md matches the rule files
(run: python3 tests/test_rule_examples.py)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "guard"


def check(*args, rules: Path | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(GUARD / "rule_check.py"), *args]
    if rules is not None:
        cmd += ["--rules", str(rules)]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=dict(os.environ, AEGIS_ML="0"))


def copy_rules() -> Path:
    d = Path(tempfile.mkdtemp()) / "rules"
    shutil.copytree(GUARD / "rules", d)
    return d


def edit(path: Path, fn) -> None:
    data = json.loads(path.read_text())
    fn(data)
    path.write_text(json.dumps(data, ensure_ascii=False))


class RuleExamples(unittest.TestCase):
    def test_a_rule_missing_from_capabilities_is_reported(self):
        d = copy_rules()
        edit(d / "capabilities.json", lambda c: c["findings"].pop("exfil_endpoint"))
        p = check(rules=d)
        self.assertEqual(p.returncode, 1)
        self.assertIn("evidence 'exfil_endpoint' has no meaning for attack paths", p.stdout)
        d = copy_rules()
        edit(d / "capabilities.json", lambda c: c["findings"].update(no_such_rule=None))
        self.assertIn("evidence 'no_such_rule' is not left by any rule", check(rules=d).stdout)

    def test_every_example_holds(self):
        p = check()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_rules_md_is_current(self):
        p = check("--doc", "--check")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_a_weakened_rule_breaks_its_examples(self):
        d = copy_rules()
        edit(d / "rules.json", lambda r: next(x for x in r["rules"] if x["id"] == "decode_then_exec").update(within_lines=0))
        p = check(rules=d)
        self.assertEqual(p.returncode, 1)
        self.assertIn("static/decode_then_exec", p.stdout)
        self.assertIn("should match but passed", p.stdout)

    def test_a_rule_without_examples_is_reported(self):
        d = copy_rules()
        edit(d / "rules.json", lambda r: r["rules"].append({"id": "eval_anywhere", "title": "eval", "detector": "first_line",
                                                            "signal": "exec", "text": "normalized", "files": "code"}))
        edit(d / "examples" / "hard.json", lambda e: e["examples"].pop("pth_exec"))
        p = check(rules=d)
        self.assertEqual(p.returncode, 1)
        self.assertIn("static/eval_anywhere: no 'hit' example", p.stdout)
        self.assertIn("hard/pth_exec: no 'miss' example", p.stdout)

    def test_an_example_for_a_removed_rule_is_reported(self):
        d = copy_rules()
        edit(d / "post.json", lambda p: p.update(rules=[r for r in p["rules"] if r["id"] != "new_package"]))
        p = check(rules=d)
        self.assertEqual(p.returncode, 1)
        self.assertIn("post/new_package: example for a rule that is not in the rule files", p.stdout)


if __name__ == "__main__":
    unittest.main()
