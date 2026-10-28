"""Rules after the scan (run: python3 tests/test_post_rules.py): a project first published < 30 days ago -> REVIEW."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"


def hook(project: Path, command: str, ages: dict, mode="auto", osv_ok=True, vdiff=None, late=None):
    patch = f"""
import scan_engine
from scan_engine import ScanFeatures, Verdict
AGES = {json.dumps(ages)}
def fake(pkgs, *a, **k):
    out = []
    for n, v in pkgs:
        f = ScanFeatures(name=n, version=v, resolved_version=v or "1.0", fetch_ok=True)
        f.package_age_days = AGES.get(n)
        out.append(Verdict("BLOCK" if n == "bad" else "ALLOW", 0.1, ["t"], f))
    return out
scan_engine.scan_packages = fake
import post_rules
post_rules.osv_reachable = lambda *a, **k: {osv_ok!r}
import version_diff
VDIFF = {(vdiff or {})!r}
version_diff.check = lambda n, v, *a, **k: VDIFF.get(n)
LATE = {(late or {})!r}
version_diff.late_file = lambda meta, v, *a, **k: LATE.get((meta.get("info") or {{}}).get("name"))
from sources import pypi
pypi.metadata = lambda n: {{"info": {{"name": n}}, "releases": {{}}}}
"""
    code = f"import sys, runpy\nsys.path.insert(0, {str(IMPL)!r})\n{patch}\nrunpy.run_path({str(IMPL / 'hooks/pretooluse_check.py')!r}, run_name='__main__')\n"
    ev = {"tool_name": "Bash", "cwd": str(project), "tool_input": {"command": command}}
    r = subprocess.run([sys.executable, "-c", code], input=json.dumps(ev), capture_output=True, text=True, timeout=60,
                       env={**os.environ, "AEGIS_MODE": mode, "AEGIS_SYSTEM_POLICY": str(project / "none.json")})
    out = json.loads(r.stdout)["hookSpecificOutput"] if r.stdout.strip() else None
    return out, json.loads((project / ".aegis/last_review.json").read_text())


with tempfile.TemporaryDirectory() as t:
    p = Path(t)
    out, rec = hook(p, "pip install fastjsonx==0.1", {"fastjsonx": 3})
    assert out and out["permissionDecision"] == "deny" and "first registered on PyPI only recently" in out["permissionDecisionReason"], out
    assert rec["packages"][0]["evidence"][0]["rule"] == "new_package" and rec["packages"][0]["new_package_days"] == 3
    assert "[AegisPilot] fastjsonx 0.1 held · newly registered package" in out["permissionDecisionReason"]
    out, _ = hook(p, "pip install fastjsonx==0.1", {"fastjsonx": 3}, mode="user")
    assert out and out["permissionDecision"] == "ask" and "newly registered package" in out["permissionDecisionReason"]
    assert hook(p, "pip install requests", {"requests": 5000})[0] is None              # an old project: unchanged
    assert hook(p, "pip install oldpkg", {"oldpkg": 30.5})[0] is None                  # boundary: 30 days and older pass
    out, rec = hook(p, "pip install bad==1.0", {"bad": 2})                              # BLOCK stays BLOCK (never lowered)
    assert out["permissionDecision"] == "deny" and rec["packages"][0]["verdict"] == "BLOCK"
    (p / ".aegis/policy.json").write_text(json.dumps({"allow": [{"package": "fastjsonx", "version": "0.1", "approver": "team lead"}]}))
    assert hook(p, "pip install fastjsonx==0.1", {"fastjsonx": 3})[0] is None          # a person's allow-list entry wins
# known malicious release: BLOCK, even when the release was deleted from PyPI (OSV still knows it)
sys.path.insert(0, str(IMPL))
import post_rules as PR  # noqa: E402
import scan_engine as se  # noqa: E402
orig = se.query_osv
se.query_osv = lambda n, v: [{"id": "MAL-2025-6794", "summary": "Malicious code in num2words (PyPI)"}] if (n, v) == ("num2words", "0.5.15") else []
try:
    gone = se.Verdict("NEEDS_HUMAN_REVIEW", 0.5, ["x"], se.ScanFeatures(name="num2words", version="0.5.15", fetch_error="version 0.5.15 not on PyPI"))
    assert PR.apply(gone, "0.5.15") == ("BLOCK", {"rule": "known_malicious", "ids": ["MAL-2025-6794"]})
    ok = se.Verdict("ALLOW", 0.0, [], se.ScanFeatures(name="num2words", version="0.5.14", fetch_ok=True))
    assert PR.apply(ok, "0.5.14") == ("ALLOW", None)
    takeover = se.ScanFeatures(name="ctx", version="0.2.6", fetch_ok=True)
    takeover.osv_vulns = [{"id": "PYSEC-2022-199", "summary": "", "details": "The ctx hosted project on PyPI was taken over via user account compromise"}]
    assert PR.apply(se.Verdict("NEEDS_HUMAN_REVIEW", 0.4, [], takeover))[0] == "BLOCK"
    plain = se.ScanFeatures(name="pyyaml", version="5.3.1", fetch_ok=True)
    plain.osv_vulns = [{"id": "GHSA-8q59-q68h-6hv4", "summary": "Improper Input Validation in PyYAML"}]
    assert PR.apply(se.Verdict("BLOCK", 0.6, [], plain)) == ("BLOCK", None)            # an ordinary CVE is not "malicious"
finally:
    se.query_osv = orig
# typosquat alone -> REVIEW, except long-established projects and separator/case-only differences
def squat(name, pop, d, age):
    f = se.ScanFeatures(name=name, version="1.0", fetch_ok=True)
    f.min_edit_distance, f.closest_popular_name, f.package_age_days = d, pop, age
    return PR.apply(se.Verdict("ALLOW", 0.15, [], f))
assert squat("requets", "requests", 1, 3) == ("NEEDS_HUMAN_REVIEW", {"rule": "typosquat", "of": "requests"})
assert squat("requets", "requests", 1, 400)[0] == "NEEDS_HUMAN_REVIEW"
assert squat("grequests", "requests", 1, 5269) == ("ALLOW", None)                      # 14-year-old project
assert squat("typing_extensions", "typing-extensions", 1, 3000) == ("ALLOW", None)
assert squat("typing_ext", "typing-ext", 1, 400) == ("ALLOW", None)                     # only separators differ
assert squat("reqeusts", "requests", 2, 100) == ("NEEDS_HUMAN_REVIEW", {"rule": "typosquat", "of": "requests"})   # 2 edits on a long name
assert squat("mcp", "pip", 2, 400) == ("ALLOW", None)                                   # short names need 1 edit
with tempfile.TemporaryDirectory() as t:
    p = Path(t)
    out, rec = hook(p, "pip install oldpkg==2.0", {"oldpkg": 900}, osv_ok=False)
    assert out and out["permissionDecision"] == "deny" and "vulnerability DB" in out["permissionDecisionReason"], out
    assert rec["packages"][0]["evidence"][0]["rule"] == "osv_unavailable"
    assert "Run the same install command once more" in out["permissionDecisionReason"]
    out, rec = hook(p, "pip install oldpkg==2.0", {"oldpkg": 900}, osv_ok=True)
    assert out is None or out.get("permissionDecision") == "allow", out
# risky code new in this release: REVIEW, the agent pins the release before
with tempfile.TemporaryDirectory() as t:
    p = Path(t)
    vd = {"oldpkg": {"previous": "1.9", "safe_version": "1.9", "since": None,
                     "signals": [{"kind": "import_time", "file": "oldpkg/__init__.py", "detail": "subprocess.Popen"}]}}
    out, rec = hook(p, "pip install oldpkg==2.0", {"oldpkg": 900}, vdiff=vd)
    assert out and out["permissionDecision"] == "deny", out
    reason = out["permissionDecisionReason"]
    assert "not in the previous version" in reason and "`oldpkg==1.9`" in reason and "hijack" in reason, reason
    pkg = rec["packages"][0]
    assert pkg["evidence"][0]["rule"] == "new_risky_code" and pkg["new_risky_code"]["previous"] == "1.9"
    from scan_engine import ScanFeatures, Verdict
    f = ScanFeatures(name="x", version="2.0", fetch_ok=True); f.package_age_days = 900
    assert PR.apply(Verdict("NEEDS_HUMAN_REVIEW", 0.3, [], f), "2.0", vdiff=vd["oldpkg"])[1]["rule"] == "new_risky_code"
    assert PR.apply(Verdict("BLOCK", 0.7, [], f), "2.0", vdiff=vd["oldpkg"]) == ("BLOCK", None)
    vd["oldpkg"]["safe_version"] = "1.9; rm -rf /"                  # never reaches the instruction unvalidated
    out, rec = hook(p, "pip install oldpkg==2.0", {"oldpkg": 900}, vdiff=vd)
    assert "rm -rf" not in out["permissionDecisionReason"].split("```")[0] and "If you cannot pin an earlier version" in out["permissionDecisionReason"]
# a file added to an old release recently: REVIEW, pin the release before
with tempfile.TemporaryDirectory() as t:
    p = Path(t)
    lf = {"oldpkg": {"file": "oldpkg-2.0-py3-none-any.whl", "release_date": "2024-01-02", "added_days_after": 700,
                     "added_days_ago": 2, "safe_version": "1.9"}}
    out, rec = hook(p, "pip install oldpkg==2.0", {"oldpkg": 900}, late=lf)
    assert out and out["permissionDecision"] == "deny" and "was added recently" in out["permissionDecisionReason"], out
    assert "`oldpkg==1.9`" in out["permissionDecisionReason"]
    assert rec["packages"][0]["evidence"][0]["rule"] == "late_file" and rec["packages"][0]["late_file"]["added_days_ago"] == 2
# the score is the scanner's weighted sum and is not moved by these rules
with tempfile.TemporaryDirectory() as t:
    p = Path(t)
    _, rec = hook(p, "pip install fastjsonx==0.1 bad==1.0", {"fastjsonx": 3, "bad": 900})
    by = {r["package"]: r for r in rec["packages"]}
    assert by["fastjsonx"]["score"] == 0.1 and by["bad"]["score"] == 0.1 and "raw_score" not in by["fastjsonx"], by
# OSV unreachable during the scan: ALLOW with no OSV record -> REVIEW, nothing else changes
def clean(verdict="ALLOW", vulns=None):
    f = se.ScanFeatures(name="six", version="1.16.0", fetch_ok=True)
    f.package_age_days, f.osv_vulns = 5000, vulns or []
    return se.Verdict(verdict, 0.05, [], f)
assert PR.apply(clean(), "1.16.0", osv_ok=False) == ("NEEDS_HUMAN_REVIEW", {"rule": "osv_unavailable"})
assert PR.apply(clean(), "1.16.0", osv_ok=True) == ("ALLOW", None)
assert PR.apply(clean("BLOCK"), "1.16.0", osv_ok=False) == ("BLOCK", None)
import urllib.request as _u
_orig = _u.urlopen
try:
    def _down(*a, **k):
        raise OSError("network down")
    _u.urlopen = _down
    assert PR.osv_reachable(timeout=1) is False
    class _Empty:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, *a): return b"{}"
    _u.urlopen = lambda *a, **k: _Empty()                 # a proxy answering 200 with nothing: not trusted
    assert PR.osv_reachable(timeout=1) is False
finally:
    _u.urlopen = _orig
print("post_rules: all cases passed")
# OSV wording for a malicious release that is not a "MAL-" record (event-stream 3.3.6), without catching ordinary CVE text
assert PR._MALICIOUS.search("The NPM package `flatmap-stream` is considered malicious.")
assert not PR._MALICIOUS.search("A malicious actor could send a crafted request that crashes the parser.")
