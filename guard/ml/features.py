"""
AegisPilot ML - features of one PyPI release, defined as in the training data (PyPI metadata from BigQuery).

    from features import compute
    r = compute("requests", "2.32.3")
    r["raw"]                                # values before the log transform (for reasons); forest.vector() makes the input

- Code is read as text, never run (code_features.py).
- A release file over 20MB or one that cannot be read gives code_ok=False: the metadata model is used.
- The guard passes the PyPI JSON and the release file it already fetched (compute_from_release), so nothing is
  fetched twice; compute() fetches them itself (command-line use).
- age_days is the age of the project when it is checked: whole days from the first upload of any of its files to the
  scan time (UTC), rounded down (`now` can be given, for tests and re-measurement).
- Standard library only (urllib): the guard's own python3 runs this.
"""
import re
import json
import time
import datetime
import urllib.request
from code_features import code_features, CODE_FEATURES

PYPI = "https://pypi.org/pypi"
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com",
             "proton.me", "protonmail.com", "qq.com", "163.com"}
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
MAX_ARTIFACT = 20 * 1024 * 1024  # the same limit the benign training code was collected with
MAX_JSON = 32 * 1024 * 1024      # a PyPI project JSON larger than this is refused
UA = {"User-Agent": "AegisPilot-ML"}


def norm_name(name):
    return re.sub(r"[-_.]+", "-", name.lower())


def _get(url, timeout, limit):
    """The body of an https GET, at most `limit` bytes (ValueError past it)."""
    if not url.startswith("https://"):
        raise ValueError(f"not an https address: {url}")
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"larger than {limit >> 20}MB")
    return data


def _get_json(url):
    return json.loads(_get(url, 15, MAX_JSON))


def _t(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def fetch(name, version=None):
    """The project JSON and the release JSON."""
    proj = _get_json(f"{PYPI}/{name}/json")
    version = version or proj["info"]["version"]
    rel = _get_json(f"{PYPI}/{name}/{version}/json")
    return proj, rel, version


def first_upload(proj):
    """The first upload time of any file of the project."""
    ts = [_t(f["upload_time_iso_8601"]) for fs in proj["releases"].values() for f in fs]
    return min(ts) if ts else None


def age_days(proj, now=None, fallback=None):
    """Whole days from the first upload of the project to `now` (UTC, default: the current time), rounded down."""
    first = first_upload(proj) or fallback
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    return float(max(0, int((now - first).total_seconds() // 86400)))


def upload_features(proj, rel, now=None):
    """Six upload features, from the history up to this release; age_days at the scan time (`now`)."""
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
        "age_days": age_days(proj, now, fallback=min(history)),
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
            data = _get(f["url"], 60, MAX_ARTIFACT)
            fname = f["filename"]
        feats = code_features(data)
        del data
        return feats, fname
    except Exception as e:
        return None, f"could not read the code: {type(e).__name__}"


def compute(name, version=None, artifact_path=None, with_code=True, now=None):
    """The raw feature values of one release (fetches the PyPI JSON)."""
    t0 = time.perf_counter()
    proj, rel, version = fetch(name, version)
    return compute_from_release(name, version, proj, rel, artifact_path, with_code, _t0=t0, now=now)


def compute_from_release(name, version, proj, rel, artifact_path=None, with_code=True, _t0=None, now=None):
    """From PyPI JSON already fetched (proj = the project, rel = the release); PyPI is not asked again. With
    artifact_path that file is read, otherwise the release file is downloaded (sdist first, 20MB or less).
    now: the scan time for age_days (default: the current time)."""
    t0 = _t0 if _t0 is not None else time.perf_counter()
    t1 = time.perf_counter()
    raw = {**upload_features(proj, rel, now), **pack_features(rel)}
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

