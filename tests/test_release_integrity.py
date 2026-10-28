"""A built guard checks itself against the checksums made at build time (2026-10-23): changed, deleted and added files,
a missing manifest; a file named like a standard module next to the guard is not imported. Builds a test copy into a
temporary folder (scripts/build_dist.py test --out ... --skip-tests). run: python3 tests/test_release_integrity.py"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

with tempfile.TemporaryDirectory() as t:
    out = Path(t) / "guard"
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_dist.py"), "test", "--out", str(out), "--skip-tests"],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    manifest = json.loads((out / "RELEASE_MANIFEST.json").read_text())
    assert "guard_core.py" in manifest["files"] and "rules/rules.json" in manifest["files"]   # code and shipped rules

    def verify():
        p = subprocess.run([sys.executable, "-I", str(out / "guard_cli.py"), "verify"], capture_output=True, text=True)
        return p.returncode, p.stdout + p.stderr

    def hook(command, mode="auto"):
        ev = json.dumps({"tool_name": "Bash", "cwd": t, "tool_input": {"command": command}})
        p = subprocess.run([sys.executable, "-I", str(out / "hooks" / "pretooluse_check.py")], input=ev, capture_output=True,
                           text=True, env={**os.environ, "AASM_MODE": mode})
        return json.loads(p.stdout)["hookSpecificOutput"] if p.stdout.strip() else None

    assert verify()[0] == 0
    assert hook("ls -la") is None
    # a file named like a standard module, next to the guard and next to the hooks: not imported, but reported
    for d in (out, out / "hooks"):
        (d / "json.py").write_text('raise SystemExit("HIJACKED")\n')
    code, text = verify()
    assert code == 1 and "HIJACKED" not in text and "json.py was added after install" in text, text
    assert hook("ls -la") is None                                   # unrelated commands still pass, nothing hijacked
    for d in (out, out / "hooks"):
        (d / "json.py").unlink()
    # a changed rule file and a changed module
    rules = out / "rules" / "scoring.json"
    rules.write_text(rules.read_text().replace('"block": 0.6', '"block": 0.99'))
    code, text = verify()
    assert code == 1 and "rules/scoring.json checksum" in text, text
    out_auto = hook("pip install six==1.16.0")
    assert out_auto["permissionDecision"] == "deny" and "guard file change detected" in out_auto["permissionDecisionReason"], out_auto
    # the baseline itself removed: a finding, never re-created from what is on disk
    (out / "RELEASE_MANIFEST.json").unlink()
    code, text = verify()
    assert code == 1 and "checksum list" in text and not (out / "RELEASE_MANIFEST.json").exists(), text
print("release_integrity: all cases passed")
