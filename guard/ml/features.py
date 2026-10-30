"""
AegisPilot ML - features of one PyPI release, defined as in the training data (PyPI metadata from BigQuery).

    from features import compute, to_vector
    r = compute("requests", "2.32.3")
    r["raw"]                                                           # values before the log transform (for reasons)
    to_vector(r["raw"], bundle["features"], bundle["log_features"])   # the model input

- Code is read as text, never run (code_features.py).
- A release file over 20MB or one that cannot be read gives code_ok=False: the metadata model is used.
- The guard passes the PyPI JSON and the release file it already fetched (compute_from_release), so nothing is
  fetched twice; compute() fetches them itself (command-line use).
"""
import re
import time
import datetime
import requests
import numpy as np
from code_features import code_features, CODE_FEATURES

PYPI = "https://pypi.org/pypi"
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
             "proton.me", "protonmail.com", "qq.com", "163.com"}
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
MAX_ARTIFACT = 20 * 1024 * 1024  # the same limit the benign training code was collected with


def norm_name(name):
    return re.sub(r"[-_.]+", "-", name.lower())


def _get_json(url):
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.json()


def _t(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def fetch(name, version=None):
    """The project JSON and the release JSON."""
    proj = _get_json(f"{PYPI}/{name}/json")
    version = version or proj["info"]["version"]
    rel = _get_json(f"{PYPI}/{name}/{version}/json")
    return proj, rel, version


def upload_features(proj, rel):
    """Six upload features, from the history up to this release."""
    files = rel["urls"]
    if not files:
        raise ValueError("no files uploaded for this release")
    # first upload time of each version (versions with files only, as in the BigQuery data)
    version_time = {v: min(_t(f["upload_time_iso_8601"]) for f in fs)
                    for v, fs in proj["releases"].items() if fs}
    t_target = min(_t(f["upload_time_iso_8601"]) for f in files)
    history = [t for t in version_time.values() if t <= t_target] or [t_target]

    info = rel["info"]
    author = (info.get("author") or "").strip()
    text = f"{(info.get('author_email') or '').strip()} {(info.get('maintainer_email') or '').strip()}"
    emails = {e.lower() for e in EMAIL_RE.findall(text)}
    return {
        "n_versions": len(history),
        "age_days": (t_target - min(history)).total_seconds() / 86400,
        "files_latest": len(files),
        "free_email": int(any(e.split("@")[1] in FREE_MAIL for e in emails)),
        "email_count": len(emails),
        "author_empty": int(author == "" and not emails),
    }


def pack_features(rel):
    """Seven packaging features (and two newer definitions kept for comparison)."""
    info, files = rel["info"], rel["urls"]
    classifiers = info.get("classifiers") or []
    has_home = int((info.get("home_page") or "") != "")
    has_license = int((info.get("license") or "") != "")
    return {
        "has_wheel": int(any(f["packagetype"] == "bdist_wheel" for f in files)),
        "total_size": sum(f.get("size") or 0 for f in files),
        "n_requires": len(info.get("requires_dist") or []),
        "has_home": has_home,
        "has_license": has_license,
        "n_classifiers": len(classifiers),
        "summary_len": len(info.get("summary") or ""),
        # ---- not used by the model yet: definitions that follow newer metadata fields (for comparison) ----
        "has_home_v2": int(has_home or bool(info.get("project_urls"))),
        "has_license_v2": int(has_license or bool(info.get("license_expression"))
                              or any(c.startswith("License ::") for c in classifiers)),
    }


def pick_artifact(files):
    """The rule the benign training code was collected with: sdist first, 20MB or less."""
    files = sorted(files, key=lambda f: f["packagetype"] != "sdist")
    files = [f for f in files if (f.get("size") or 0) <= MAX_ARTIFACT]
    return files[0] if files else None


def code_part(rel, artifact_path=None):
    """The code features, or None when they cannot be computed."""
    try:
        if artifact_path:
            with open(artifact_path, "rb") as fh:
                data = fh.read()
            fname = artifact_path
        else:
            f = pick_artifact(rel["urls"])
            if f is None:
                return None, "no release file of 20MB or less"
            data = requests.get(f["url"], timeout=60).content
            fname = f["filename"]
        feats = code_features(data)
        del data
        return feats, fname
    except Exception as e:
        return None, f"could not read the code: {type(e).__name__}"


def compute(name, version=None, artifact_path=None, with_code=True):
    """The raw feature values of one release (fetches the PyPI JSON)."""
    t0 = time.perf_counter()
    proj, rel, version = fetch(name, version)
    return compute_from_release(name, version, proj, rel, artifact_path, with_code, _t0=t0)


def compute_from_release(name, version, proj, rel, artifact_path=None, with_code=True, _t0=None):
    """From PyPI JSON already fetched (proj = the project, rel = the release); PyPI is not asked again. With
    artifact_path that file is read, otherwise the release file is downloaded (sdist first, 20MB or less)."""
    t0 = _t0 if _t0 is not None else time.perf_counter()
    t1 = time.perf_counter()
    raw = {**upload_features(proj, rel), **pack_features(rel)}
    code_ok, code_src = False, None
    if with_code:
        feats, code_src = code_part(rel, artifact_path)
        if feats is not None:
            raw.update(feats)
            code_ok = True
    t2 = time.perf_counter()
    return {
        "package": norm_name(name), "version": version,
        "raw": raw, "code_ok": code_ok, "code_source": code_src,
        "timing_sec": {"pypi_info": round(t1 - t0, 2), "features": round(t2 - t1, 2),
                       "total": round(t2 - t0, 2)},
    }


META_KEYS = ["n_versions", "age_days", "files_latest", "free_email", "email_count", "author_empty",
             "has_wheel", "total_size", "n_requires", "has_home", "has_license", "n_classifiers", "summary_len"]


def compute_local(name, version, meta, artifact_path=None):
    """From a metadata dict and a local release file, without PyPI (demos and offline tests)."""
    t0 = time.perf_counter()
    raw = {k: meta[k] for k in META_KEYS}
    raw["has_home_v2"] = meta.get("has_home_v2", raw["has_home"])
    raw["has_license_v2"] = meta.get("has_license_v2", raw["has_license"])
    code_ok, code_src = False, None
    if artifact_path:
        feats, code_src = code_part(None, artifact_path)
        if feats is not None:
            raw.update(feats)
            code_ok = True
    t1 = time.perf_counter()
    return {
        "package": norm_name(name), "version": version,
        "raw": raw, "code_ok": code_ok, "code_source": code_src,
        "timing_sec": {"pypi_info": 0.0, "features": round(t1 - t0, 2), "total": round(t1 - t0, 2)},
    }


def to_vector(raw, features, log_features):
    """The model input: the training order and log transform."""
    return np.array([[np.log1p(raw[f]) if f in log_features else raw[f] for f in features]], dtype=float)
