"""The ML model: hash-checked install (automatic on first use, or ml-install) and use (run: python3
tests/test_ml_install.py). Offline: fake model files and a fake download, so nothing is downloaded. Version 2 installs
the model files only (no environment)."""
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

    # not installed: on by default, downloaded on first use. Offline here: the download fails, the check goes on with
    # rules only, says why, and does not retry on every check
    assert not ml_bridge.installed() and ml_bridge.ml_enabled()
    assert ml_install.status(t / "ml").startswith("not installed yet")
    calls = []
    real_fetch = ml_install._fetch
    ml_install._fetch = lambda url, dest, timeout=120: (calls.append(url), (_ for _ in ()).throw(OSError("offline")))
    r = ml_bridge.ml_predict("requests")
    assert r["ok"] is False and r.get("not_installed") and "automatic download failed" in r["error"], r
    assert len(calls) == 1 and calls[0].startswith(real["release_url"]) and calls[0].endswith(".json.gz")
    r = ml_bridge.ml_predict("requests")
    assert "tried again later" in r["error"] and len(calls) == 1, r                  # remembered: no second attempt
    assert "the last automatic download failed" in ml_install.status(t / "ml")
    assert ml_install.auto_install(t / "ml", now=__import__("time").time() + ml_install.AUTO_RETRY_SECONDS + 1)
    assert len(calls) == 2                                                             # tried again after the pause
    # a download already running in another check: this one does not wait or start a second one
    (t / "ml" / ".auto_failed").unlink()
    (t / "ml" / ".auto.lock").write_text("")
    assert "another check" in ml_install.auto_install(t / "ml") and len(calls) == 2
    (t / "ml" / ".auto.lock").unlink()
    ml_install._fetch = real_fetch
    # AEGIS_ML=0: nothing is downloaded
    os.environ["AEGIS_ML"] = "0"
    assert ml_bridge.ml_predict("requests").get("disabled") and len(calls) == 2
    os.environ.pop("AEGIS_ML")
    # removed with ml-uninstall: the marker keeps it off and nothing is downloaded again
    ml_install.opt_out_marker(t / "ml").write_text("")
    assert not ml_bridge.ml_enabled() and "ml-uninstall" in ml_install.status(t / "ml")
    assert "ml-uninstall" in ml_bridge.ml_predict("requests")["error"] and len(calls) == 2
    ml_install.opt_out_marker(t / "ml").unlink()
    (t / "ml" / ".auto_failed").unlink(missing_ok=True)

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

    # automatic download that works: the same hash check as ml-install, and the lock is gone afterwards
    ml_install._fetch = lambda url, dest, timeout=120: dest.write_bytes(
        {"a.joblib": b"model a", "b.joblib": b"model b"}[url.rsplit("/", 1)[1]])
    assert ml_install.auto_install(t / "auto") is None and ml_install.check_models(t / "auto" / "models") is None
    assert not (t / "auto" / ".auto.lock").exists() and not (t / "auto" / ".auto_failed").exists()
    # a download with another hash is not used and is remembered as a failure
    ml_install._fetch = lambda url, dest, timeout=120: dest.write_bytes(b"something else")
    why = ml_install.auto_install(t / "auto2")
    assert why and "SHA-256" in why and not (t / "auto2" / "models" / "a.joblib").exists()
    ml_install._fetch = real_fetch

    # a changed file is refused at install, and nothing of that install is moved in
    (src / "b.joblib").write_bytes(b"tampered")
    try:
        ml_install.install_models(t / "other" / "models", src)
        raise AssertionError("installed a file with another hash")
    except ValueError as e:
        assert "SHA-256" in str(e)
    assert not list((t / "other" / "models").iterdir())

    # the model files alone make it installed (no environment any more); a version 1 venv is only mentioned
    assert ml_bridge.installed() and ml_bridge.ml_enabled()
    assert ml_install.status(t / "ml").startswith("installed")
    (t / "ml" / "venv" / "bin").mkdir(parents=True)
    assert "no longer used" in ml_install.status(t / "ml") and (t / "ml" / "venv").is_dir()

    # a model file changed after install is not used: the bridge checks before every run
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
    # ml-uninstall leaves the marker that stops the automatic download
    r = subprocess.run([sys.executable, "-I", str(GUARD / "guard_cli.py"), "ml-uninstall", "--yes"], capture_output=True,
                       text=True, stdin=subprocess.DEVNULL, env={**os.environ})
    assert r.returncode == 0 and ml_install.opted_out(t / "ml") and "not downloaded again" in r.stdout, r.stdout

# no environment and no pip any more
assert not hasattr(ml_install, "install_venv")
with tempfile.TemporaryDirectory() as t2:
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

# a result without a score (a changed or broken scan.py) gives no ML verdict instead of an exception in the check
with tempfile.TemporaryDirectory() as t3:
    real_run, real_check, real_installed = ml_bridge.subprocess.run, ml_install.check_models, ml_bridge.installed
    for out in ("{}", "[1, 2]"):
        ml_bridge.subprocess.run = lambda args, out=out, **k: subprocess.CompletedProcess(args, 0, out, "")
        ml_install.check_models = lambda folder: None
        ml_bridge.installed = lambda: True
        os.environ["AEGIS_ML"] = "1"
        r = ml_bridge.ml_predict("requests")
        assert r["ok"] is False and ("incomplete" in r["error"] or "not a JSON object" in r["error"]), r
    ml_bridge.subprocess.run, ml_install.check_models, ml_bridge.installed = real_run, real_check, real_installed

# installing the ML model never lowers a verdict: the stricter of the rules alone and the ML path is kept
import rule_engine  # noqa: E402
import scan_engine as se  # noqa: E402
f = se.ScanFeatures(name="x", version="1")
f.ml = {"ok": True, "ml_score": 0.0, "threshold": 0.2, "alert": False, "level": "pass"}
real_rules, real_ml = se._compute_verdict_rules, rule_engine.score_ml
se._compute_verdict_rules = lambda feat: se.Verdict("NEEDS_HUMAN_REVIEW", 0.3, ["rules"], feat)
rule_engine.score_ml = lambda rs, feat: ("ALLOW", 0.05, ["ml"])
assert se.compute_verdict(f).verdict == "NEEDS_HUMAN_REVIEW"
rule_engine.score_ml = lambda rs, feat: ("BLOCK", 0.7, ["ml"])
assert se.compute_verdict(f).verdict == "BLOCK"
se._compute_verdict_rules, rule_engine.score_ml = real_rules, real_ml
print("ml_install: all cases passed")
