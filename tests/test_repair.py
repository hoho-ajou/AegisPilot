"""Restoring a changed guard to its official build (guard/repair.py, guard_cli.py repair; 2026-10-23). Builds two
copies (a damaged install and a source) into a temporary folder. run: python3 tests/test_repair.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guard"))
import integrity  # noqa: E402
import repair  # noqa: E402


def build(out: Path) -> None:
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_dist.py"), "test", "--out", str(out), "--skip-tests"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


with tempfile.TemporaryDirectory() as t:
    t = Path(t)
    target, src = t / "installed", t / "official"
    build(target)
    build(src)
    info = json.loads((target / "BUILD_INFO.json").read_text())
    origin = subprocess.run(["git", "remote", "get-url", "origin"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    assert info.get("source") == (origin or None), info                           # where repair fetches the commit back

    # damage the install: a changed rule, a planted module, a deleted file
    rules = target / "rules" / "scoring.json"
    rules.write_text(rules.read_text().replace('"block": 0.6', '"block": 0.99'))
    (target / "json.py").write_text("raise SystemExit('HIJACKED')\n")
    (target / "policy.py").unlink()
    assert len(integrity.check_release(target)) == 3

    # without a terminal the typed confirmation is replaced by --yes (an agent in auto mode); without either it stops
    p = subprocess.run([sys.executable, "-I", str(target / "guard_cli.py"), "repair", "--from", str(src)],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert p.returncode == 2 and "--yes" in p.stdout, p.stdout + p.stderr
    # --dry-run shows the plan and changes nothing
    p = subprocess.run([sys.executable, "-I", str(target / "guard_cli.py"), "repair", "--from", str(src), "--dry-run"],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert p.returncode == 0 and "rules/scoring.json" in p.stdout and "json.py" in p.stdout and "policy.py" in p.stdout, p.stdout
    assert len(integrity.check_release(target)) == 3

    s, files, origin = repair.prepare(target, src, t)
    assert repair.plan(target, files) == {"replace": ["rules/scoring.json"], "remove": ["json.py"], "add": ["policy.py"]}
    # the repair itself, as the agent runs it from the integrity card (repair --yes)
    home = t / "home"
    p = subprocess.run([sys.executable, "-I", str(target / "guard_cli.py"), "repair", "--from", str(src), "--yes"],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, env={**os.environ, "HOME": str(home)})
    assert p.returncode == 0 and "Check after repair: OK" in p.stdout, p.stdout + p.stderr
    assert integrity.check_release(target) == []
    q = next((home / ".aegis" / "quarantine").iterdir())
    assert (q / "json.py").read_text().startswith("raise") and '"block": 0.99' in (q / "rules" / "scoring.json").read_text()
    assert json.loads((q / "REPAIR.json").read_text())["remove"] == ["json.py"]

    # a damaged source is not a repair
    (src / "guard_core.py").write_text("# changed\n")
    try:
        repair.prepare(target, src, t)
        raise AssertionError("a damaged source must be refused")
    except repair.RepairError as e:
        assert "differ from its own checksums" in str(e)
    # no recorded source and no --from: says what to do
    os.remove(target / "BUILD_INFO.json")
    try:
        repair.prepare(target, None, t)
        raise AssertionError("no source must be refused")
    except repair.RepairError as e:
        assert "--from" in str(e)
print("repair: all cases passed")
