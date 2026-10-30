"""
AegisPilot - bridge to the optional ML model (guard/ml).

The model needs scikit-learn and shap, which the guard's own python3 does not have. So `ml/scan.py --json` runs as a
separate process with the python of the ML environment, and only its JSON result comes back. Nothing extra is needed
for the guard itself: without the ML environment the verdict is rule-based only.

Set up by the person, once: `python3 guard_cli.py ml-install` (ml_install.py) makes ~/.aegis/ml/ with
  venv/      the environment (ml/requirements.txt, exact versions)
  models/    the model files (ml/models.json: names and SHA-256)

Settings
  AEGIS_ML          0 off, 1 on              default: on when the ML environment is installed
  AEGIS_ML_DIR      the ML folder            default: ~/.aegis/ml. It names the python the guard runs, so a built guard
                                             reads it from the settings files only (switches.py)
  AEGIS_ML_TIMEOUT  seconds per package      default: 45

Rules
  - Never raises. On any failure it returns {"ok": False, "error": ...} and the verdict is rule-based.
  - The model files are checked against models.json (SHA-256) before every run: they are loaded with joblib (pickle),
    which runs code, and ~/.aegis/ml can be written by anything that runs as the user.
  - The model reads the release file the guard already downloaded (handoff); without it, it downloads the file itself
    by the rule it was trained with (sdist first, 20MB or less).
"""
import json
import os
import subprocess
import tempfile
from pathlib import Path

import switches

ML_CODE = Path(__file__).resolve().parent / "ml"


def ml_dir() -> Path:
    return Path(switches.get("AEGIS_ML_DIR") or Path.home() / ".aegis" / "ml")


def ml_python() -> Path:
    return ml_dir() / "venv" / "bin" / "python"


def models_dir() -> Path:
    return ml_dir() / "models"


def timeout() -> int:
    try:
        return int(os.environ.get("AEGIS_ML_TIMEOUT", "45"))
    except ValueError:
        return 45


def installed() -> bool:
    """The ML environment and both model files are there (not yet checked against their hashes)."""
    try:
        import ml_install
        models = ml_install.spec()["models"]
        return ml_python().exists() and all((models_dir() / m["file"]).is_file() for m in models.values())
    except (OSError, ValueError, KeyError, TypeError):
        return False


def ml_enabled() -> bool:
    """AEGIS_ML=0 off, AEGIS_ML=1 on, unset = on when installed (a fresh install runs rules only)."""
    flag = os.environ.get("AEGIS_ML")
    if flag is not None:
        return flag != "0"
    return installed()


def ml_predict(name: str, version: str | None = None, handoff: dict | None = None) -> dict:
    """Score one package with the ML model. Always returns a dict; ok=False means no ML verdict.
    handoff = the collection step's result {"proj", "rel", "artifact": {"path", ...}|None}: the model then does not ask
    PyPI again."""
    if not ml_enabled():
        return {"ok": False, "disabled": True, "error": "ML is off (AEGIS_ML=0 or not installed)"}
    import ml_install
    problem = ml_install.check_models(models_dir())
    if problem:
        return {"ok": False, "error": f"ML model files not used: {problem} (run guard_cli.py ml-install)"}
    if not ml_python().exists():
        return {"ok": False, "error": f"ML environment not found: {ml_python()} (run guard_cli.py ml-install)"}

    cmd = [str(ml_python()), "-E", "-s", str(ML_CODE / "scan.py"), name] + ([version] if version else []) + \
          ["--json", "--models", str(models_dir())]
    tmp_handoff = None
    try:
        if handoff:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
                json.dump({"schema": "aegis.handoff/1", "package": name, "version": version, **handoff}, fh)
                tmp_handoff = fh.name
            cmd += ["--handoff", tmp_handoff]
        # -E -s: no PYTHON* variables, no user site folder (not -I: scan.py imports the modules next to it)
        p = subprocess.run(cmd, cwd=ML_CODE, capture_output=True, text=True, timeout=timeout())
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"exceeded {timeout()}s"}
    except Exception as e:
        return {"ok": False, "error": f"run failed: {type(e).__name__}: {e}"}
    finally:
        if tmp_handoff:
            try:
                os.unlink(tmp_handoff)
            except OSError:
                pass

    try:
        r = json.loads(p.stdout)
    except json.JSONDecodeError:
        tail = (p.stderr or p.stdout or "").strip().splitlines()[-1:] or [""]
        return {"ok": False, "error": f"could not parse result: {tail[0][:200]}"}
    if "error" in r:
        return {"ok": False, "error": r["error"]}

    reasons = r.get("reasons", {})
    return {
        "ok": True,
        "package": r.get("package"),
        "version": r.get("version"),
        "ml_score": r["ml_score"],
        "threshold": r["threshold"],
        "alert": bool(r["alert"]),
        "model": r.get("model"),
        "code_analyzed": r.get("code_analyzed"),
        "code_source": r.get("code_source"),
        # evidence shown to the developer: code behavior first, then the package profile
        "reasons": reasons.get("code_behavior", []) + reasons.get("package_profile", []),
        "notes": r.get("notes", []),
        "all_contributions": r.get("all_contributions", []),
        "elapsed_sec": r.get("elapsed_sec"),
    }


def to_schema_item(ml: dict, name: str, version: str | None, ecosystem: str = "pypi") -> dict | None:
    """One results[] item for the report and dashboard."""
    if not ml or not ml.get("ok"):
        return None
    contribs = sorted(ml.get("all_contributions", []), key=lambda t: -t.get("contribution", 0))[:5]
    return {
        "package_name": name,
        "package_version": ml.get("version") or version or "",
        "ecosystem": ecosystem,
        "is_flagged": ml["alert"],
        "ml_score": ml["ml_score"],
        "model": ml.get("model") or "ml",
        "triggered_features": [
            {"feature": t["feature"], "value": t.get("value"),
             "importance": round(min(1.0, max(0.0, t.get("contribution", 0))), 4),
             "desc": t.get("desc")}
            for t in contribs
        ],
        "notes": [{"feature": t["feature"], "value": t.get("value"), "desc": t.get("desc")}
                  for t in ml.get("notes", [])],
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        sys.exit("usage: python3 ml_bridge.py PACKAGE [VERSION]")
    res = ml_predict(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print(json.dumps(res, ensure_ascii=False, indent=2))
