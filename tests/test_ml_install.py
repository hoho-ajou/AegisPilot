"""The optional ML model: hash-checked install and use (run: python3 tests/test_ml_install.py). Offline: fake model
files and a fake environment, so nothing is downloaded or installed."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(GUARD))
with tempfile.TemporaryDirectory() as t:
    t = Path(t)
    os.environ["AEGIS_ML_DIR"] = str(t / "ml")
    os.environ.pop("AEGIS_ML", None)
    import guard_paths  # noqa: E402
    import ml_bridge  # noqa: E402
    import ml_install  # noqa: E402

    # the shipped list names two models with their SHA-256, downloaded from an https release
    real = ml_install.spec()
    assert set(real["models"]) == {"full", "meta"} and real["release_url"].startswith("https://github.com/")
    assert all(len(m["sha256"]) == 64 for m in real["models"].values())

    # not installed: rules only, and the bridge says so instead of failing
    assert not ml_bridge.installed() and not ml_bridge.ml_enabled()
    assert ml_bridge.ml_predict("requests")["ok"] is False
    assert ml_install.status(t / "ml").startswith("not installed")

    # a fake list of models; install from a folder copies only files with the listed SHA-256
    src = t / "src"
    src.mkdir()
    (src / "a.joblib").write_bytes(b"model a")
    (src / "b.joblib").write_bytes(b"model b")
    fake = {"release_url": "https://example.invalid/", "models": {
        "full": {"file": "a.joblib", "size": 7, "sha256": hashlib.sha256(b"model a").hexdigest()},
        "meta": {"file": "b.joblib", "size": 7, "sha256": hashlib.sha256(b"model b").hexdigest()}}}
    ml_install.spec = lambda: fake
    ml_install.install_models(t / "ml" / "models", src)
    assert ml_install.check_models(t / "ml" / "models") is None

    # a changed file is refused at install, and nothing of that install is moved in
    (src / "b.joblib").write_bytes(b"tampered")
    try:
        ml_install.install_models(t / "other" / "models", src)
        raise AssertionError("installed a file with another hash")
    except ValueError as e:
        assert "SHA-256" in str(e)
    assert not list((t / "other" / "models").iterdir())

    # a model file changed after install is not used: the bridge checks before every run
    (t / "ml" / "venv" / "bin").mkdir(parents=True)
    (t / "ml" / "venv" / "bin" / "python").write_text("")
    assert ml_bridge.installed() and ml_bridge.ml_enabled()
    (t / "ml" / "models" / "a.joblib").write_bytes(b"tampered")
    r = ml_bridge.ml_predict("requests")
    assert r["ok"] is False and "differs" in r["error"], r
    assert ml_install.status(t / "ml").startswith("not used")

    # AEGIS_ML=0 turns it off
    os.environ["AEGIS_ML"] = "0"
    assert not ml_bridge.ml_enabled()

    # the agent running the install or removal is the person's call
    assert guard_paths.command_changes_guard_install("python3 -I ~/x/guard/guard_cli.py ml-install --yes")
    assert guard_paths.command_changes_guard_install("python3 guard/guard_cli.py ml-uninstall")

    # outside a terminal the commands need --yes
    r = subprocess.run([sys.executable, "-I", str(GUARD / "guard_cli.py"), "ml-uninstall"], capture_output=True,
                       text=True, stdin=subprocess.DEVNULL, env={**os.environ})
    assert r.returncode == 2 and "--yes" in r.stdout, r.stdout

# the environment is made without the current folder on the path and with pip isolated from local config
with tempfile.TemporaryDirectory() as t2:
    calls = []
    real_run = ml_install.subprocess.run
    ml_install.subprocess.run = lambda args, **k: calls.append((args, k))
    ml_install.install_venv(Path(t2) / "venv", log=lambda *_: None)
    ml_install.subprocess.run = real_run
    assert all("-I" in a and k.get("cwd") == "/" for a, k in calls), calls
    assert "--isolated" in calls[-1][0] and "https://pypi.org/simple" in calls[-1][0]
    # removing the ML folder never follows a link on the way (a planted ~/.aegis -> ~ would delete another folder)
    other = Path(t2) / "other" / "ml"
    other.mkdir(parents=True)
    (Path(t2) / "home").mkdir()
    (Path(t2) / "home" / ".aegis").symlink_to(Path(t2) / "other")
    try:
        ml_install.uninstall(Path(t2) / "home" / ".aegis" / "ml")
        raise AssertionError("followed a linked folder")
    except ValueError:
        pass
    assert other.is_dir()

# installing the ML model never lowers a verdict: the stricter of the rules alone and the ML path is kept
import rule_engine  # noqa: E402
import scan_engine as se  # noqa: E402
f = se.ScanFeatures(name="x", version="1")
f.ml = {"ok": True, "ml_score": 0.0, "threshold": 0.2, "alert": False}
real_rules, real_ml = se._compute_verdict_rules, rule_engine.score_ml
se._compute_verdict_rules = lambda feat: se.Verdict("NEEDS_HUMAN_REVIEW", 0.3, ["rules"], feat)
rule_engine.score_ml = lambda rs, feat: ("ALLOW", 0.05, ["ml"])
assert se.compute_verdict(f).verdict == "NEEDS_HUMAN_REVIEW"
rule_engine.score_ml = lambda rs, feat: ("BLOCK", 0.7, ["ml"])
assert se.compute_verdict(f).verdict == "BLOCK"
se._compute_verdict_rules, rule_engine.score_ml = real_rules, real_ml
print("ml_install: all cases passed")
