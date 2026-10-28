"""
ML anomaly detection bridge (ml_bridge)

Calls the ML model (guard/r3) from scan_engine.py, which runs on the default python3.
The model needs scikit-learn and shap, so `r3_scan.py --json` runs as a separate process with the python of
its own venv and only the result (JSON) comes back. Nothing extra has to be installed for the guard itself.

Settings (environment variables, defaults when unset)
  R3_DIR      ML model folder                default: guard/r3
  R3_PYTHON   python of the model's venv     default: r3/venv/bin/python next to this file (a development checkout
                                             also looks up to three levels above and under ~)
  In a released guard R3_DIR and R3_PYTHON are read from the settings files only (switches.py), like the other switches
  an agent could use against the guard: the guard runs that python.
  R3_TIMEOUT  time limit per package         default: 45s
  AASM_ML     0 off, 1 on                    default: on if the model's python and models exist, otherwise off

Rules
  - Never raises, whatever fails. On failure it returns {"ok": False, "error": ...} and
    scan_engine goes ahead with the rule-based verdict.
  - The model downloads the package file itself, by the same rule it was trained with (sdist first, 20MB or less).
    (A wheel has no setup.py, so setup-related features would differ; the file the pipeline downloaded is not passed.)
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import switches  # noqa: E402

# The ML code lives in guard/r3. Its dependencies (scikit-learn, shap, pyzipper) are not in the default python, so it runs
# as a subprocess with R3_PYTHON. Without R3_PYTHON, look for an `r3/venv` next to this file; a development checkout also
# looks up to two folders above it and under ~ (where the team keeps the model's venv). A released guard does not: a
# python found in a folder the agent can write would run inside the guard.
R3_DIR = Path(switches.get("R3_DIR") or str(Path(__file__).resolve().parent / "r3"))


def _find_r3_python() -> Path | None:
    here = Path(__file__).resolve()
    bases = [here.parent] if switches.released() else [*here.parents[:3], Path.home()]
    for base in bases:
        cand = base / "r3" / "venv" / "bin" / "python"
        if cand.exists():
            return cand
    return None


_FOUND_PYTHON = Path(switches.get("R3_PYTHON")) if switches.get("R3_PYTHON") else _find_r3_python()
R3_PYTHON = _FOUND_PYTHON or Path(sys.executable)
R3_TIMEOUT = int(os.environ.get("R3_TIMEOUT", "45"))
# ML can run only with the model's python and the trained models (models are not in git; they are distributed separately)
ML_AVAILABLE = bool(_FOUND_PYTHON and _FOUND_PYTHON.exists() and (R3_DIR / "models" / "r3_full.joblib").exists())


def ml_enabled() -> bool:
    """AASM_ML=0 off, AASM_ML=1 on, unset = on only when ML_AVAILABLE (so a fresh install without the ML model runs rules only)."""
    flag = os.environ.get("AASM_ML")
    if flag is not None:
        return flag != "0"
    return ML_AVAILABLE


def ml_predict(name: str, version: str | None = None, handoff: dict | None = None) -> dict:
    """Score one package with the ML model. Always returns a dict; ok=False means no ML verdict.
    handoff = the collection step's result {"proj", "rel", "artifact": {"path", ...}|None}. With it the model does not query PyPI again."""
    if not ml_enabled():
        return {"ok": False, "disabled": True, "error": "turned off by AASM_ML=0"}
    if not (R3_DIR / "r3_scan.py").exists() or not R3_PYTHON.exists():
        return {"ok": False, "error": f"ML model not found (R3_DIR={R3_DIR}, R3_PYTHON={R3_PYTHON})"}

    cmd = [str(R3_PYTHON), "r3_scan.py", name] + ([version] if version else []) + ["--json"]
    tmp_handoff = None
    try:
        if handoff:
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
                json.dump({"schema": "aasm.handoff/1", "package": name, "version": version, **handoff}, fh)
                tmp_handoff = fh.name
            cmd += ["--handoff", tmp_handoff]
        p = subprocess.run(cmd, cwd=R3_DIR, capture_output=True, text=True, timeout=R3_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"exceeded {R3_TIMEOUT}s"}
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
    """Convert to a results[] item of schemas/ml_result.schema.json (for the report and dashboard)"""
    if not ml or not ml.get("ok"):
        return None
    contribs = sorted(ml.get("all_contributions", []), key=lambda t: -t.get("contribution", 0))[:5]
    return {
        "package_name": name,
        "package_version": ml.get("version") or version or "",
        "ecosystem": ecosystem,
        "is_flagged": ml["alert"],
        "ml_score": ml["ml_score"],
        "model": ml.get("model") or "r3",
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
