"""
AegisPilot ML - scores one PyPI release: ml_score and the reasons a developer is shown.

    python scan.py requests                     # latest version
    python scan.py requests 2.32.3 --json       # JSON only (what the guard reads)
    python scan.py mypkg 0.1.0 --artifact ./mypkg-0.1.0.tar.gz   # read the code of a local release file
    python scan.py demo 0.1.0 --artifact demo-0.1.0.tar.gz --meta meta.json   # no PyPI at all (demo / offline)

Runs in its own environment (scikit-learn, shap; see requirements.txt), started by guard/ml_bridge.py. The models are
the full model when the code could be read and the metadata model otherwise; --models names their folder, and the
guard checks their SHA-256 (models.json) before it starts this.
"""
import sys
import json
import time
import argparse
import joblib
import numpy as np
from features import compute, compute_local, compute_from_release, to_vector

from pathlib import Path
_HERE = Path(__file__).resolve().parent
MODEL_FILES = {k: v["file"] for k, v in json.loads((_HERE / "models.json").read_text())["models"].items()}
MODELS_DIR = _HERE / "models"
_cache = {}


def _load(kind):
    """The model and its SHAP explainer, loaded once."""
    if kind not in _cache:
        import shap
        bundle = joblib.load(MODELS_DIR / MODEL_FILES[kind])
        _cache[kind] = (bundle, shap.TreeExplainer(bundle["model"]))
    return _cache[kind]


def _shap_row(explainer, X):
    """The contributions to the "malicious" class, whatever the shap version returns."""
    sv = explainer.shap_values(X)
    if isinstance(sv, list):
        sv = sv[1]
    sv = np.asarray(sv)
    if sv.ndim == 3:
        sv = sv[..., 1]
    return sv[0]


# ---------------- feature -> sentence for the developer ----------------
def _size(b):
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.0f}{unit}"
        b /= 1024
    return f"{b:.1f}TB"


DESC = {
    "n_versions":       lambda v: f"only {int(v)} version(s) published so far",
    "age_days":         lambda v: ("first upload, or uploaded right after it" if v < 1
                                   else f"uploaded {v:.0f} days after the first version"),
    "files_latest":     lambda v: f"{int(v)} release file(s) in this version",
    "free_email":       lambda v: "registered with a free mail address (gmail and similar)" if v else "no free mail address",
    "email_count":      lambda v: "no e-mail address registered" if v == 0 else f"{int(v)} e-mail address(es) registered",
    "author_empty":     lambda v: "no author information" if v else "author information present",
    "has_wheel":        lambda v: "source distribution only, no wheel" if not v else "a wheel is published",
    "total_size":       lambda v: f"release files total {_size(v)}",
    "n_requires":       lambda v: "no dependencies" if v == 0 else f"{int(v)} dependencies",
    "has_home":         lambda v: "no homepage" if not v else "has a homepage",
    "has_license":      lambda v: "no license information" if not v else "has license information",
    "n_classifiers":    lambda v: "no classifiers" if v == 0 else f"{int(v)} classifiers",
    "summary_len":      lambda v: "empty summary" if v == 0 else f"summary of {int(v)} characters",
    "n_py":             lambda v: f"only {int(v)} Python file(s)",
    "code_lines":       lambda v: f"{int(v)} lines of code in total",
    "max_line_len":     lambda v: (f"one line of {int(v):,} characters: code may be hidden in it" if v > 1000
                                   else f"longest code line: {int(v)} characters"),
    "obfuscation_rate": lambda v: f"{v:.1f} hiding signals (dynamic execution, decoding, encoded strings) per 1,000 lines",
    "exec_cnt":         lambda v: f"{int(v)} place(s) that run a string as code (exec, eval, compile)",
    "decode_cnt":       lambda v: f"{int(v)} place(s) that decode hidden data (base64, zlib and similar)",
    "long_blob_cnt":    lambda v: f"{int(v)} encoded string(s) over 200 characters",
    "process_cnt":      lambda v: f"{int(v)} place(s) that run external commands",
    "network_cnt":      lambda v: f"{int(v)} place(s) with network access",
    "sensitive_cnt":    lambda v: f"{int(v)} trace(s) of data theft (webhooks, .ssh and similar)",
    "setup_exec":       lambda v: "setup.py runs a string as code" if v else "no dynamic execution in setup.py",
    "setup_decode":     lambda v: "setup.py decodes hidden data" if v else "no decoding in setup.py",
    "setup_process":    lambda v: "setup.py runs external commands during installation" if v else "setup.py runs no external commands",
    "setup_network":    lambda v: "setup.py goes online during installation" if v else "no network access in setup.py",
    "setup_sensitive":  lambda v: "setup.py has traces of data theft" if v else "no traces of data theft in setup.py",
    "install_hook":     lambda v: "setup.py takes over the installation (cmdclass)" if v else "no installation hook",
    # code features version 3
    "auto_process":     lambda v: f"external commands run as soon as it is installed or imported ({int(v)})",
    "auto_network":     lambda v: f"network access as soon as it is installed or imported ({int(v)})",
    "auto_exec":        lambda v: f"strings run as code as soon as it is installed or imported ({int(v)})",
    "decode_exec_chain": lambda v: f"hidden data decoded and run as code right away ({int(v)})",
}


MIN_CONTRIB = 0.02  # smaller contributions are not shown as package-profile reasons

# severe signals that run at install time: always reported when present, whatever their contribution
SEVERE = ["decode_exec_chain", "auto_exec", "auto_process", "setup_process", "install_hook", "setup_exec",
          "setup_decode", "setup_network", "setup_sensitive", "sensitive_cnt"]
# code behavior signals (everything else describes the package profile)
BEHAVIOR = SEVERE + ["auto_network", "obfuscation_rate", "exec_cnt", "decode_cnt", "long_blob_cnt",
                     "process_cnt", "network_cnt", "max_line_len"]


def _present(f, raw):
    """The behavior is really in the code."""
    v = raw.get(f, 0)
    return v > 1000 if f == "max_line_len" else v > 0


def _item(f, raw, c):
    v = raw[f]
    return {"feature": f, "value": v, "contribution": round(float(c), 3),
            "desc": DESC.get(f, lambda x: f"{f} = {x}")(v)}


def scan(name, version=None, artifact_path=None, top_k=3, meta_path=None, handoff_path=None):
    t0 = time.perf_counter()
    if handoff_path:  # what the guard already collected (no second PyPI query or download)
        with open(handoff_path, encoding="utf-8") as fh:
            h = json.load(fh)
        art = (h.get("artifact") or {}).get("path")
        feat = compute_from_release(name, version or h["version"], h["proj"], h["rel"], artifact_path=art)
    elif meta_path:  # demo / offline: a metadata file instead of PyPI
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        feat = compute_local(name, version or "0.0.0", meta, artifact_path=artifact_path)
    else:
        feat = compute(name, version, artifact_path=artifact_path)
    kind = "full" if feat["code_ok"] else "meta"
    bundle, explainer = _load(kind)
    raw = feat["raw"]

    X = to_vector(raw, bundle["features"], bundle["log_features"])
    score = float(bundle["model"].predict_proba(X)[0, 1])
    alert = score >= bundle["threshold"]
    contrib = dict(zip(bundle["features"], _shap_row(explainer, X)))

    # 1) risky behavior found in the code: present, and severe or raising the score
    severe = [f for f in SEVERE if f in contrib and _present(f, raw)]            # every severe signal
    other = sorted([f for f in BEHAVIOR if f not in SEVERE and f in contrib
                    and _present(f, raw) and contrib[f] > 0], key=lambda f: -contrib[f])[:2]
    code_behavior = [_item(f, raw, contrib[f]) for f in severe + other]

    # 2) package profile: other features that raised the score enough
    prof = [f for f in sorted(contrib, key=lambda f: -contrib[f])
            if f not in BEHAVIOR and contrib[f] >= MIN_CONTRIB][:2]
    package_profile = [_item(f, raw, contrib[f]) for f in prof]

    # 3) passed, but with a severe signal: reported as a note (the verdict stays)
    notes = [] if alert else [x for x in code_behavior if x["feature"] in SEVERE]

    # for analysis: the features that raised the score most (also when passed)
    all_up = [_item(f, raw, contrib[f]) for f in sorted(contrib, key=lambda f: -contrib[f])
              if contrib[f] > 0][:top_k]

    return {
        "package": feat["package"], "version": feat["version"],
        "ml_score": round(score, 3),
        "threshold": round(bundle["threshold"], 3),
        "alert": alert,
        "model": f"ml_{kind}",
        "code_analyzed": feat["code_ok"],
        "code_source": feat["code_source"],
        "reasons": {"code_behavior": code_behavior if alert else [],
                    "package_profile": package_profile if alert else []},
        "notes": notes,                                            # severe signals of a passed package
        "top_features": (code_behavior + package_profile) if alert else [],   # older readers
        "all_contributions": all_up,                               # for analysis
        "elapsed_sec": round(time.perf_counter() - t0, 2),
    }


def _print_human(r):
    status = "ALERT: this may be an unknown malicious package" if r["alert"] else "passed: no strong risk signal"
    print(f"\n[AegisPilot ML] {r['package']}=={r['version']}")
    print(f"  ml_score  : {r['ml_score']:.3f}  (alert at {r['threshold']:.3f})")
    print(f"  verdict   : {status}")
    print(f"  model     : {r['model']}  (code {'read' if r['code_analyzed'] else 'not read: ' + str(r['code_source'])})")
    if r["reasons"]["code_behavior"]:
        print("  risky behavior in the code:")
        for t in r["reasons"]["code_behavior"]:
            print(f"    - {t['desc']}")
    if r["reasons"]["package_profile"]:
        print("  package profile:")
        for t in r["reasons"]["package_profile"]:
            print(f"    - {t['desc']}  ({t['contribution']:+.3f})")
    if r["notes"]:
        print("  note: low score, but something runs at install time")
        for t in r["notes"]:
            print(f"    - {t['desc']}")
    print(f"  time      : {r['elapsed_sec']}s\n")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="AegisPilot ML: score one PyPI release")
    ap.add_argument("package")
    ap.add_argument("version", nargs="?", default=None)
    ap.add_argument("--artifact", default=None, help="a local release file whose code is read")
    ap.add_argument("--meta", default=None, help="a metadata JSON file instead of PyPI (demo / offline)")
    ap.add_argument("--handoff", default=None, help="what the guard collected: JSON with proj, rel, artifact.path")
    ap.add_argument("--models", default=None, help="the folder with the model files (default: models/ here)")
    ap.add_argument("--json", action="store_true", help="print JSON only")
    a = ap.parse_args()
    if a.models:
        MODELS_DIR = Path(a.models)
    try:
        result = scan(a.package, a.version, artifact_path=a.artifact, meta_path=a.meta, handoff_path=a.handoff)
    except Exception as e:
        err = {"package": a.package, "version": a.version, "error": f"{type(e).__name__}: {e}"}
        print(json.dumps(err, ensure_ascii=False) if a.json else f"[AegisPilot ML] failed: {err['error']}")
        sys.exit(1)
    if a.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_human(result)
