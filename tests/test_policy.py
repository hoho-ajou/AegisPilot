"""Offline tests for the policy stage (run: python3 tests/test_policy.py).

Unit rules of policy.decide, then the real hook with the network scan replaced by fixed verdicts."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(IMPL))
import policy as P  # noqa: E402

pol = {"deny": [{"package": "Left_Pad", "versions": "*", "reason": "banned internally", "approver": "security team", "source": "system"},
                {"package": "old-lib", "versions": ["1.0"], "reason": "only 1.0 banned", "source": "project"}],
       "allow": [{"package": "corp-utils", "version": "1.4.2", "reason": "internal service", "approver": "team lead", "expires": "2099-01-01", "source": "project"},
                 {"package": "stale", "version": "1.0", "expires": "2020-01-01", "source": "project"},
                 {"package": "danger", "version": "2.0", "source": "project"}]}
assert P.decide(pol, "left-pad", "9.9", "ALLOW")[0] == "BLOCK"                       # name normalized, any version
assert P.decide(pol, "old-lib", "1.0", "ALLOW")[0] == "BLOCK" and P.decide(pol, "old-lib", "1.1", "ALLOW") == ("ALLOW", None)
v, n = P.decide(pol, "corp-utils", "1.4.2", "NEEDS_HUMAN_REVIEW")
assert v == "ALLOW" and n["approver"] == "team lead" and n["action"] == "allow"
assert P.decide(pol, "corp-utils", "1.4.3", "NEEDS_HUMAN_REVIEW") == ("NEEDS_HUMAN_REVIEW", None)   # exact version only
assert P.decide(pol, "corp-utils", None, "NEEDS_HUMAN_REVIEW") == ("NEEDS_HUMAN_REVIEW", None)       # unpinned: no allow
v, n = P.decide(pol, "stale", "1.0", "NEEDS_HUMAN_REVIEW", today="2026-10-15")
assert v == "NEEDS_HUMAN_REVIEW" and n["action"] == "allow_expired"
v, n = P.decide(pol, "danger", "2.0", "BLOCK")
assert v == "BLOCK" and n["action"] == "allow_ignored"                                # never lowers a BLOCK


def hook(project: Path, command: str, verdicts: dict, mode="user"):
    patch = f"""
import scan_engine
from scan_engine import ScanFeatures, Verdict
V = {json.dumps(verdicts)}
def fake(pkgs, *a, **k):
    out = []
    for name, ver in pkgs:
        f = ScanFeatures(name=name, version=ver, resolved_version=ver or "1.0", fetch_ok=True)
        out.append(Verdict(V.get(name, "ALLOW"), 0.3, ["test"], f))
    return out
scan_engine.scan_packages = fake
"""
    code = f"import sys, runpy\nsys.path.insert(0, {str(IMPL)!r})\n{patch}\nrunpy.run_path({str(IMPL / 'hooks/pretooluse_check.py')!r}, run_name='__main__')\n"
    ev = {"tool_name": "Bash", "cwd": str(project), "tool_input": {"command": command}}
    r = subprocess.run([sys.executable, "-c", code], input=json.dumps(ev), capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AEGIS_MODE": mode, "AEGIS_SYSTEM_POLICY": str(project / "no-system-policy.json")})
    out = json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None
    rec = json.loads((project / ".aegis/last_review.json").read_text())
    return out, rec


with tempfile.TemporaryDirectory() as t:
    proj = Path(t)
    (proj / ".aegis").mkdir()
    (proj / ".aegis/policy.json").write_text(json.dumps({
        "deny": [{"package": "leftpad", "versions": "*", "reason": "banned internally", "approver": "security team"}],
        "allow": [{"package": "corp-utils", "version": "1.4.2", "reason": "internal service", "approver": "team lead", "expires": "2099-01-01"}]}))
    # allowed REVIEW -> silent pass, recorded with who allowed it
    out, rec = hook(proj, "pip install corp-utils==1.4.2", {"corp-utils": "NEEDS_HUMAN_REVIEW"})
    assert out is None and rec["verdict"] == "ALLOW" and rec["packages"][0]["policy"]["approver"] == "team lead", (out, rec)
    # same package, other version: still asked
    out, rec = hook(proj, "pip install corp-utils==1.5.0", {"corp-utils": "NEEDS_HUMAN_REVIEW"})
    assert out and out["permissionDecision"] == "ask"
    # allow entry never lowers a BLOCK
    out, rec = hook(proj, "pip install corp-utils==1.4.2", {"corp-utils": "BLOCK"})
    assert out and out["permissionDecision"] == "deny" and rec["packages"][0]["policy"]["action"] == "allow_ignored"
    # denied package: blocked although the scan found nothing; the auto card says why and what to do
    out, rec = hook(proj, "pip install leftpad", {}, mode="auto")
    assert out and out["permissionDecision"] == "deny" and rec["verdict"] == "BLOCK", (out, rec)
    assert "deny list" in out["permissionDecisionReason"] and "policy file" in out["permissionDecisionReason"]
    assert rec["packages"][0]["evidence"][0]["rule"] == "policy_deny"
    out, rec = hook(proj, "pip install leftpad", {}, mode="user")
    assert out and out["permissionDecision"] == "deny"
    # the system file wins and the agent cannot weaken it from the project
    sysfile = proj / "system.json"
    sysfile.write_text(json.dumps({"deny": [{"package": "corp-utils", "versions": "*", "reason": "banned company-wide"}]}))
    os.environ["AEGIS_SYSTEM_POLICY"] = str(sysfile)
    import importlib; importlib.reload(P)
    v, n = P.decide(P.load(proj), "corp-utils", "1.4.2", "NEEDS_HUMAN_REVIEW")
    assert v == "BLOCK" and n["source"] == "system"
    # a broken policy file changes nothing (and says so)
    (proj / ".aegis/policy.json").write_text("{broken")
    assert P.load(proj)["notes"]

print("policy: all cases passed")
