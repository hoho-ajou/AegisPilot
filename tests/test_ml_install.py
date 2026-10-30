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
print("ml_install: all cases passed")
