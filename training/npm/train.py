"""
Train and measure the npm models of AegisPilot ML (npm_full with registry history, npm_pkg without), the way the PyPI
model v2 was made: time split for malicious samples, install ages 0-30 days, two-stage alert, the lowest threshold that
meets every false-alarm goal on held-out benign predictions, then one measurement on the test sets.

    python3 train.py --mal mal.jsonl --benign benign.jsonl --cutoff 2026-04-01 --out OUT
                     [--final-benign final.jsonl]   # an independent benign set, measured once at the end
                     [--joint-pypi pypi.csv]        # the "one model for both" comparison (see joint_experiment)

Needs scikit-learn, numpy, shap, joblib (guard/ml/requirements.txt). Writes into OUT:
  aegis-ml-npm-full-1.json.gz, aegis-ml-npm-pkg-1.json.gz   the models, in the guard's format (guard/ml/forest.py)
  models_npm.json                                           the "npm" block for guard/ml/models.json
  metrics.json, REPORT.md                                   every number measured
  *.joblib                                                  the scikit-learn bundles (never committed)

Rules kept from the PyPI work: the thresholds are chosen before the test sets are looked at, from out-of-fold
predictions on the training benign packages; the test sets are measured once; nothing is re-chosen after.
"""
import argparse
import datetime
import gzip
import hashlib
import json
import math
import random
import sys
import zlib
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from common import NF, ML, INSTALL_AGES, read_jsonl, parse_t, now_utc

sys.path.insert(0, str(ML))
import forest as pure_forest      # noqa: E402

DAY = 86400.0
GOALS = {"all": 0.05, "top": 0.02, "longtail": 0.08, "new": 0.08, "local": 0.02}   # benign REVIEW rate, each install age
SEED = 20261115


# ------------------------------------------------------------------------------------------------- data

def load(paths):
    rows = []
    for p in paths:
        for r in read_jsonl(p):
            if "skipped" not in r:
                rows.append(r)
    return rows


def group_of(r):
    return r["kind"] if r["label"] == 0 else "malicious"


def is_test_benign(name, pct):
    return zlib.crc32(name.encode()) % 100 < pct


def age_at(r, days_after_publish):
    """age_days if this version were checked `days_after_publish` days after it was published."""
    pub = parse_t(r.get("t_published")) or parse_t(r["t_scan"])
    created = parse_t(r.get("t_created")) or pub
    when = pub + datetime.timedelta(days=days_after_publish)
    return float(max(0, int((when - created).total_seconds() // DAY)))


USE_AGE = True          # False while the model without registry features (npm_pkg) is trained: no install ages
MODEL_VERSION = 1       # --model-version: number in the model file names and the release name
MAL_ALL_AGES = False    # --mal-all-ages: malicious rows stand for every install age 0-30 (PyPI R3f), not only up to found


def install_ages(r):
    """The install ages a row stands for in training: malicious - every age up to when it was found (it was installable
    until then), or every age with --mal-all-ages; new benign - all; established benign - only as collected (they were
    installed at that age)."""
    if not (USE_AGE and r.get("registry_ok")):
        return [None]
    if r["label"] == 1 and MAL_ALL_AGES:
        return list(INSTALL_AGES)
    if r["label"] == 1:
        pub = parse_t(r.get("t_published")) or parse_t(r["t_scan"])
        found = max(0, int((parse_t(r["t_scan"]) - pub).total_seconds() // DAY))
        return [a for a in INSTALL_AGES if a <= found] or [0]
    if r["kind"] == "new":
        return list(INSTALL_AGES)
    return [None]


def with_age(r, a):
    raw = dict(r["raw"])
    if a is not None and r.get("registry_ok"):
        raw["age_days"] = age_at(r, a)
    return raw


def dedupe(rows, feats, cap=3):
    """At most `cap` malicious rows with exactly the same features (campaigns publish hundreds of copies)."""
    seen, out = Counter(), []
    for r in rows:
        if r["label"] == 1:
            key = tuple(r["raw"].get(f, 0) for f in feats)
            seen[key] += 1
            if seen[key] > cap:
                continue
        out.append(r)
    return out


def matrix(raws, feats):
    logs = set(NF.LOG_FEATURES)
    X = np.array([[math.log1p(r[f]) if f in logs else float(r[f]) for f in feats] for r in raws], dtype=np.float64)
    return X.astype(np.float32)


# ------------------------------------------------------------------------------------------------- model

def fit(X, y, w, seed=SEED):
    from sklearn.ensemble import RandomForestClassifier
    m = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=seed)
    w = np.asarray(w, dtype=np.float64)
    for c in (0, 1):                                   # both classes weigh the same in total
        w[y == c] *= len(y) / (2 * max(w[y == c].sum(), 1e-9))
    m.fit(X, y, sample_weight=w)
    return m


MIN_ALERT = 0.05      # the lowest threshold considered: rows scoring below it never need SHAP


def _shap_values(model, X, feats):
    """Exact TreeSHAP of class 1: the shap package when installed, else the guard's own (forest.py, slower)."""
    try:
        import shap
        sv = shap.TreeExplainer(model).shap_values(X)
        return sv[1] if isinstance(sv, list) else (sv[..., 1] if sv.ndim == 3 else sv)
    except ImportError:
        import convert
        f = pure_forest.Forest(convert.convert({"model": model, "features": feats}, [], 0.5, 0.5))
        return np.array([f.shap([float(v) for v in row])[1] for row in X])


def behavior_flags(model, X, raws, feats, scores=None):
    """Per row: a code behavior signal (SEVERE present, or another BEHAVIOR present with a positive SHAP value), as
    ml/scan.py decides it. Rows scoring under MIN_ALERT can never alert: no SHAP for them."""
    sev = [f for f in NF.SEVERE if f in feats]
    flags = np.array([any(r.get(f, 0) > 0 for f in sev) for r in raws], dtype=bool)
    other = [feats.index(f) for f in NF.BEHAVIOR if f in feats and f not in NF.SEVERE]
    need = ~flags if scores is None else (~flags & (np.asarray(scores) >= MIN_ALERT))
    need &= np.array([any(r.get(feats[j], 0) > 0 for j in other) for r in raws], dtype=bool) if other else False
    todo = np.where(need)[0]
    if len(todo):
        sv = _shap_values(model, X[todo], feats)
        for k, i in enumerate(todo):
            flags[i] = any(raws[i].get(feats[j], 0) > 0 and sv[k, j] > 0 for j in other)
    return flags


def oof(rows, feats, folds=5):
    """Out-of-fold scores and behavior flags of every (row, install age), grouped by package name."""
    from sklearn.model_selection import GroupKFold
    names = sorted({r["name"] for r in rows})
    k = max(2, min(folds, len(names)))
    gkf = GroupKFold(n_splits=k)
    idx = np.arange(len(rows))
    groups = [r["name"] for r in rows]
    out = []                                           # (row index, install age, score, flag)
    for tr, te in gkf.split(idx, groups=groups):
        tr_raws, tr_y, tr_w = [], [], []
        for i in tr:
            ages = install_ages(rows[i])
            for a in ages:
                tr_raws.append(with_age(rows[i], a)); tr_y.append(rows[i]["label"]); tr_w.append(1 / len(ages))
        m = fit(matrix(tr_raws, feats), np.array(tr_y), tr_w)
        te_rows = [(i, a) for i in te for a in eval_ages(rows[i])]
        raws = [with_age(rows[i], a) for i, a in te_rows]
        X = matrix(raws, feats)
        p = m.predict_proba(X)[:, 1]
        fl = behavior_flags(m, X, raws, feats, p)
        out += [(i, a, float(s), bool(f)) for (i, a), s, f in zip(te_rows, p, fl)]
    return out


def eval_ages(r):
    """The install ages a row is measured at: new benign and malicious at every age (malicious only up to when it was
    found); established benign as collected."""
    if not (USE_AGE and r.get("registry_ok")):
        return [None]
    if r["label"] == 0 and r["kind"] != "new":
        return [None]
    return install_ages(r) if r["label"] == 1 else list(INSTALL_AGES)


def rates(preds, rows, thr):
    """Benign REVIEW rate per (group, install age) and malicious REVIEW recall per age, at threshold thr."""
    fp = defaultdict(lambda: [0, 0])
    tp = defaultdict(lambda: [0, 0])
    for i, a, s, f in preds:
        r = rows[i]
        review = s >= thr and f
        if r["label"] == 0:
            for g in (r["kind"], "all"):
                ages = [a] if a is not None else list(INSTALL_AGES)   # an established package counts at every age
                for aa in ages:
                    fp[(g, aa)][0] += review; fp[(g, aa)][1] += 1
        else:
            tp[a][0] += review; tp[a][1] += 1
    return ({k: v[0] / v[1] for k, v in fp.items() if v[1]}, {k: v[0] / v[1] for k, v in tp.items() if v[1]},
            dict(fp), dict(tp))


def choose_threshold(preds, rows, goals=GOALS):
    """The lowest threshold (4 decimals, rounded up) at which every benign group meets its goal at every install age."""
    cands = sorted({math.ceil(s * 1e4) / 1e4 for _, _, s, _ in preds} | {round(x, 4) for x in np.linspace(0.05, 0.99, 95)})
    for t in cands:
        fpr, _, _, _ = rates(preds, rows, t)
        if all(v <= goals.get(g, goals["all"]) for (g, _), v in fpr.items()):
            return t
    return 0.99


# ------------------------------------------------------------------------------------------------- conversion

def to_json(model, feats, thr, variant, data_note):
    sys.path.insert(0, str(ML))
    import convert
    d = convert.convert({"model": model, "features": feats, "variant": variant, "trained_at": str(datetime.date.today()),
                         "age_definition": None}, NF.LOG_FEATURES, thr, thr, data_note)
    d["age_definition"] = "age_days = log1p(floor((scan time UTC - creation of the npm package) / 1 day))"
    return d


def write_gz(d, path):
    with open(path, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as fh:
        fh.write(json.dumps(d, separators=(",", ":")).encode())
    data = Path(path).read_bytes()
    return {"file": Path(path).name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def parity(d, model, raws, feats):
    """The guard's pure-Python forest against scikit-learn on the same rows: largest score difference, flips."""
    f = pure_forest.Forest(d)
    sk = model.predict_proba(matrix(raws, feats))[:, 1]
    diffs = [abs(f.predict(f.vector(r)) - s) for r, s in zip(raws, sk)]
    return max(diffs) if diffs else 0.0


# ------------------------------------------------------------------------------------------------- one model

def train_one(variant, feats, train_rows, test_rows, final_rows, out):
    global USE_AGE
    USE_AGE = "age_days" in feats
    print(f"\n=== {variant}: {len(feats)} features, train {len(train_rows)}, test {len(test_rows)}")
    preds = oof(train_rows, feats)
    thr = choose_threshold(preds, train_rows)
    fpr, tpr, _, _ = rates(preds, train_rows, thr)
    print(f"threshold {thr}  (OOF) benign max {max(fpr.values()):.3f}, malicious recall at age 0 {tpr.get(0, tpr.get(None, 0)):.3f}")

    raws, y, w = [], [], []
    for r in train_rows:
        ages = install_ages(r)
        for a in ages:
            raws.append(with_age(r, a)); y.append(r["label"]); w.append(1 / len(ages))
    model = fit(matrix(raws, feats), np.array(y), w)

    def measure(rows):
        items = [(i, a) for i, r in enumerate(rows) for a in eval_ages(r)]
        rr = [with_age(rows[i], a) for i, a in items]
        if not rr:
            return [], {}
        X = matrix(rr, feats)
        p = model.predict_proba(X)[:, 1]
        fl = behavior_flags(model, X, rr, feats, p)
        pr = [(i, a, float(s), bool(f)) for (i, a), s, f in zip(items, p, fl)]
        fpr, tpr, fpc, tpc = rates(pr, rows, thr)
        by_kind = defaultdict(lambda: [0, 0])
        for i, a, s, f in pr:
            if rows[i]["label"] == 1 and a in (0, None):
                by_kind[rows[i]["kind"]][0] += s >= thr and f; by_kind[rows[i]["kind"]][1] += 1
        alert_by_age = defaultdict(lambda: [0, 0])
        for i, a, s, f in pr:
            if rows[i]["label"] == 1:
                alert_by_age[str(a)][0] += s >= thr; alert_by_age[str(a)][1] += 1
        alert_only = sum(1 for i, a, s, f in pr if rows[i]["label"] == 1 and a in (0, None) and s >= thr) / max(
            1, sum(1 for i, a, s, f in pr if rows[i]["label"] == 1 and a in (0, None)))
        return pr, {"benign_review_rate": {f"{g}@{a}": round(v, 4) for (g, a), v in sorted(fpr.items(), key=str)},
                    "benign_counts": {f"{g}@{a}": c for (g, a), c in sorted(fpc.items(), key=str)},
                    "malicious_review_recall": {str(a): round(v, 4) for a, v in tpr.items()},
                    "malicious_alert_recall_age0": round(alert_only, 4),
                    "malicious_alert_recall": {a: round(v[0] / v[1], 4) for a, v in alert_by_age.items() if v[1]},
                    "malicious_recall_by_kind_age0": {k: round(v[0] / v[1], 4) for k, v in by_kind.items() if v[1]},
                    "malicious_counts": {str(a): c for a, c in tpc.items()}}

    _, test_m = measure(test_rows)
    final_m = measure(final_rows)[1] if final_rows else None
    d = to_json(model, feats, thr, variant, f"train {len(train_rows)} rows; see metrics.json")
    fname = {"npm_full": f"aegis-ml-npm-full-{MODEL_VERSION}.json.gz", "npm_pkg": f"aegis-ml-npm-pkg-{MODEL_VERSION}.json.gz"}[variant]
    entry = write_gz(d, out / fname)
    sample = [with_age(r, a) for r in random.Random(SEED).sample(test_rows, min(500, len(test_rows))) for a in eval_ages(r)][:2000]
    par = parity(d, model, sample, feats)
    import joblib
    joblib.dump({"model": model, "features": feats, "variant": variant, "threshold": thr}, out / f"{variant}.joblib")
    imp = sorted(zip(feats, model.feature_importances_), key=lambda t: -t[1])[:15]
    return {"threshold": thr, "oof_benign_rate": {f"{g}@{a}": round(v, 4) for (g, a), v in sorted(fpr.items(), key=str)},
            "oof_malicious_recall": {str(a): round(v, 4) for a, v in tpr.items()},
            "test": test_m, "final": final_m, "model_file": entry, "parity_max_diff": par,
            "importance_top15": [(f, round(float(v), 4)) for f, v in imp]}


# ------------------------------------------------------------------------------------------------- one model for both?

# PyPI raw feature -> the npm feature that measures the same thing (guard/ml/features.py, code_features.py)
COMMON = [("n_versions", "n_versions"), ("age_days", "age_days"), ("email_count", "email_count"),
          ("free_email", "free_email"), ("author_empty", "author_empty"), ("total_size", "total_size"),
          ("n_requires", "n_deps"), ("has_home", "has_home"), ("has_license", "has_license"),
          ("summary_len", "summary_len"), ("n_py", "n_js"), ("code_lines", "code_lines"),
          ("max_line_len", "max_line_len"), ("obfuscation_rate", "obfuscation_rate"), ("exec_cnt", "exec_cnt"),
          ("decode_cnt", "decode_cnt"), ("long_blob_cnt", "long_blob_cnt"), ("process_cnt", "process_cnt"),
          ("network_cnt", "network_cnt"), ("sensitive_cnt", "sensitive_cnt"), ("setup_exec", "install_exec"),
          ("setup_decode", "install_decode"), ("setup_process", "install_process"),
          ("setup_network", "install_network"), ("setup_sensitive", "install_sensitive"),
          ("install_hook", "has_install_script"), ("auto_process", "auto_process"), ("auto_network", "auto_network"),
          ("auto_exec", "auto_exec"), ("decode_exec_chain", "decode_exec_chain")]


def joint_experiment(pypi_csv, train_rows, test_rows):
    """Can one model serve both? A forest on the 30 concepts both ecosystems have, trained on PyPI + npm, against a
    forest on the same 30 trained on npm only, both measured on the npm test set (and the joint one on PyPI's test rows
    when the CSV has split=test). pypi_csv: one row per PyPI release with the raw PyPI features, label (1 malicious),
    and optionally split (train/test)."""
    import csv
    from sklearn.metrics import roc_auc_score
    names = [n for _, n in COMMON]
    py_tr, py_te = [], []
    with open(pypi_csv, newline="") as fh:
        for rec in csv.DictReader(fh):
            raw = {n: float(rec[p] or 0) for p, n in COMMON}
            (py_te if rec.get("split") == "test" else py_tr).append((raw, int(float(rec["label"]))))

    def npm(rows):
        # only rows with the registry document: the shared concepts include n_versions and age_days, which rows
        # without it do not have (their raw lacks the registry features)
        return [(with_age(r, 0), r["label"]) for r in rows if r.get("registry_ok")]

    n_tr, n_te = npm(train_rows), npm(test_rows)

    def go(train):
        X = matrix([r for r, _ in train], names)
        y = np.array([l for _, l in train])
        return fit(X, y, np.ones(len(y)))

    def score(m, data):
        X = matrix([r for r, _ in data], names)
        y = np.array([l for _, l in data])
        p = m.predict_proba(X)[:, 1]
        res = {"auc": round(float(roc_auc_score(y, p)), 4) if len(set(y)) == 2 else None}
        neg = np.sort(p[y == 0])
        for fp in (0.02, 0.05):
            if len(neg):
                t = neg[min(len(neg) - 1, int(math.ceil(len(neg) * (1 - fp))))]
                res[f"recall_at_fp{int(fp * 100)}"] = round(float((p[y == 1] > t).mean()), 4) if (y == 1).any() else None
        return res

    sep, joint = go(n_tr), go(n_tr + py_tr)
    out = {"npm_test": {"npm_only": score(sep, n_te), "joint": score(joint, n_te)}, "rows": {
        "pypi_train": len(py_tr), "pypi_test": len(py_te), "npm_train": len(n_tr), "npm_test": len(n_te)}}
    if py_te:
        out["pypi_test"] = {"joint": score(joint, py_te), "pypi_only": score(go(py_tr), py_te)}
    return out


# ------------------------------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mal", nargs="+", required=True)
    ap.add_argument("--benign", nargs="+", required=True)
    ap.add_argument("--final-benign", nargs="*", default=[])
    ap.add_argument("--cutoff", required=True, help="malicious samples found on or after this day (UTC) are the test set")
    ap.add_argument("--benign-test-pct", type=int, default=25)
    ap.add_argument("--joint-pypi", default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--mal-all-ages", action="store_true",
                    help="malicious rows stand for (and are measured at) every install age 0-30, as PyPI R3f")
    ap.add_argument("--model-version", type=int, default=1)
    a = ap.parse_args()
    global MAL_ALL_AGES, MODEL_VERSION
    MAL_ALL_AGES, MODEL_VERSION = a.mal_all_ages, a.model_version
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    cutoff = parse_t(a.cutoff + "T00:00:00Z")

    mal, ben = load(a.mal), load(a.benign)
    final = load(a.final_benign) if a.final_benign else []
    seen_final = {r["name"] for r in final}
    ben = [r for r in ben if r["name"] not in seen_final]          # the final set stays unseen
    mal_tr = [r for r in mal if parse_t(r["t_scan"]) < cutoff]
    mal_te = [r for r in mal if parse_t(r["t_scan"]) >= cutoff]
    ben_te = [r for r in ben if is_test_benign(r["name"], a.benign_test_pct)]
    ben_tr = [r for r in ben if not is_test_benign(r["name"], a.benign_test_pct)]
    feats_dedupe = NF.PKG_FEATURES
    train = dedupe(mal_tr + ben_tr, feats_dedupe)
    test = dedupe(mal_te + ben_te, feats_dedupe)
    print(f"malicious {len(mal)} (train {len(mal_tr)} before dedupe, test {len(mal_te)}), benign {len(ben)}, final {len(final)}")

    metrics = {"made": now_utc().isoformat(), "cutoff": a.cutoff, "goals": GOALS, "mal_all_ages": MAL_ALL_AGES,
               "model_version": MODEL_VERSION, "counts": {
        "train": Counter(group_of(r) for r in train), "test": Counter(group_of(r) for r in test),
        "final": Counter(group_of(r) for r in final)}}
    full_tr = [r for r in train if r.get("registry_ok")]
    full_te = [r for r in test if r.get("registry_ok")]
    full_fi = [r for r in final if r.get("registry_ok")]
    both = lambda rows: {r["label"] for r in rows} == {0, 1}      # noqa: E731
    metrics["npm_full"] = train_one("npm_full", NF.NPM_FEATURES, full_tr, full_te, full_fi, out) if both(full_tr) else None
    metrics["npm_pkg"] = train_one("npm_pkg", NF.PKG_FEATURES, train, test, final, out)

    # the models' block and metrics are written before the optional joint comparison, so a failure there cannot
    # lose the measured results; metrics.json is written again with the comparison added when it succeeds
    block = {"version": MODEL_VERSION,
             "release_url": f"https://github.com/hoho-ajou/AegisPilot/releases/download/ml-models-npm-{MODEL_VERSION}/",
             "models": {k: metrics[k]["model_file"] for k in ("npm_full", "npm_pkg") if metrics.get(k)},
             "thresholds": {k: {"alert": metrics[k]["threshold"], "review": metrics[k]["threshold"]}
                            for k in ("npm_full", "npm_pkg") if metrics.get(k)}}
    (out / "models_npm.json").write_text(json.dumps(block, indent=2) + "\n")
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2, default=dict) + "\n")
    if a.joint_pypi:
        metrics["joint_experiment"] = joint_experiment(a.joint_pypi, train, test)
        (out / "metrics.json").write_text(json.dumps(metrics, indent=2, default=dict) + "\n")
    print(json.dumps(metrics, indent=1, default=dict)[:6000])


if __name__ == "__main__":
    main()
