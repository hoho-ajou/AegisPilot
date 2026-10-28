"""The hook collects the Profile alongside the scan and saves rule-only attack paths per decision
(run: python3 tests/test_hook_paths.py). A slow or failing Profile never changes the verdict."""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"


def hook(project: Path, command: str, extra_patch: str = ""):
    patch = f"""
import scan_engine
from scan_engine import ScanFeatures, Verdict
def fake(pkgs, *a, **k):
    return [Verdict("BLOCK" if n == "bad" else "ALLOW", 0.7, ["test"], ScanFeatures(name=n, version=v, resolved_version=v or "1.0", fetch_ok=True))
            for n, v in pkgs]
scan_engine.scan_packages = fake
{extra_patch}
"""
    code = f"import sys, runpy\nsys.path.insert(0, {str(IMPL)!r})\n{patch}\nrunpy.run_path({str(IMPL / 'hooks/pretooluse_check.py')!r}, run_name='__main__')\n"
    ev = {"tool_name": "Bash", "cwd": str(project), "tool_input": {"command": command}}
    t = time.time()
    r = subprocess.run([sys.executable, "-c", code], input=json.dumps(ev), capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AASM_MODE": "user", "HOME": str(project / "home"), "AASM_SYSTEM_POLICY": str(project / "none.json")})
    out = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() else None
    return out, json.loads((project / ".aasm/last_review.json").read_text()), time.time() - t


with tempfile.TemporaryDirectory() as t:
    proj = Path(t)
    (proj / "home/.ssh").mkdir(parents=True)
    (proj / "home/.ssh/id_ed25519").write_text("x")
    (proj / "app.py").write_text("import bad\n")
    out, rec, _ = hook(proj, "pip install bad==1.0 good==2.0")
    did = rec["decision_id"]
    assert out == "deny" and [p["pid"] for p in rec["packages"]] == ["P01", "P02"]
    saved = json.loads((proj / f".aasm/attack_paths/{did}.json").read_text())
    assert saved["decision_id"] == did and saved["profile_cache"] == "miss"
    assert json.loads((proj / ".aasm/profile.json").read_text())["fingerprint"]
    out, rec2, _ = hook(proj, "pip install bad==1.0")
    assert json.loads((proj / f".aasm/attack_paths/{rec2['decision_id']}.json").read_text())["profile_cache"] == "hit"
    (proj / "app.py").write_text("import bad\nimport os\n")          # the code changed: collected again
    out, rec3, _ = hook(proj, "pip install bad==1.0")
    assert json.loads((proj / f".aasm/attack_paths/{rec3['decision_id']}.json").read_text())["profile_cache"] == "miss"
    # nothing flagged: no paths are built
    out, rec4, _ = hook(proj, "pip install good==2.0")
    assert out is None and not (proj / f".aasm/attack_paths/{rec4['decision_id']}.json").exists()
    # slow Profile: cut off after PROFILE_WAIT_SECONDS, verdict unchanged
    out, rec5, secs = hook(proj, "pip install bad==1.0", "import env_profile, time\nenv_profile.collect_cached = lambda *a, **k: time.sleep(10)")
    assert out == "deny" and secs < 9 and not (proj / f".aasm/attack_paths/{rec5['decision_id']}.json").exists(), secs
    # failing Profile: verdict unchanged
    out, rec6, _ = hook(proj, "pip install bad==1.0", "import env_profile\nenv_profile.collect_cached = lambda *a, **k: 1/0")
    assert out == "deny" and rec6["verdict"] == "BLOCK" and not (proj / f".aasm/attack_paths/{rec6['decision_id']}.json").exists()

print("hook_paths: all cases passed")
