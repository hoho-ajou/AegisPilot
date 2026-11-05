"""
AegisPilot ML - converts a trained scikit-learn bundle (joblib) into the JSON the guard reads (forest.py).

    python convert.py BUNDLE.joblib OUT.json.gz --alert 0.2352 --review 0.2352 --log-features a,b,... [--data TEXT]

Needs scikit-learn (requirements.txt: for conversion and training only). The guard itself never loads joblib/pickle.
Floats are written as Python repr (json.dump default): no rounding, so the guard predicts exactly what scikit-learn does.
Each tree: left, right (-1 = leaf), feature, threshold, p1 (malicious fraction at every node, what predict_proba
averages) and cover (weighted_n_node_samples, for TreeSHAP).
"""
import argparse
import gzip
import json

import joblib
import sklearn

FORMAT = "aegis-forest/2"


def tree_json(est):
    t = est.tree_
    if list(est.classes_) != [0, 1]:
        raise ValueError(f"classes {est.classes_}: expected [0, 1]")
    v = t.value[:, 0, :]
    p1 = (v[:, 1] / v.sum(axis=1)).tolist()        # sklearn >= 1.4 stores fractions already; the division keeps it exact
    leaf = t.children_left == -1
    return {"left": t.children_left.tolist(), "right": t.children_right.tolist(),
            "feature": [(-1 if lf else int(f)) for f, lf in zip(t.feature, leaf)],
            "threshold": [(0.0 if lf else float(x)) for x, lf in zip(t.threshold, leaf)],
            "p1": p1, "cover": t.weighted_n_node_samples.tolist()}


def convert(bundle, log_features, alert, review, data=""):
    m = bundle["model"]
    feats = list(bundle["features"])
    if m.n_features_in_ != len(feats):
        raise ValueError("feature count differs from the model")
    return {
        "format": FORMAT,
        "features": feats,
        "log_features": [f for f in feats if f in set(log_features)],
        "thresholds": {"alert": float(alert), "review": float(review)},
        "age_definition": "age_days = log1p(floor((scan time UTC - first upload of the project) / 1 day))",
        "trees": [tree_json(e) for e in m.estimators_],
        "source": {"variant": bundle.get("variant"), "trained_at": bundle.get("trained_at"), "data": data,
                   "sklearn": sklearn.__version__, "n_estimators": len(m.estimators_),
                   "bundle_age_definition": bundle.get("age_definition")},
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle")
    ap.add_argument("out")
    ap.add_argument("--alert", type=float, required=True)
    ap.add_argument("--review", type=float, required=True)
    ap.add_argument("--log-features", required=True)
    ap.add_argument("--data", default="")
    a = ap.parse_args()
    d = convert(joblib.load(a.bundle), a.log_features.split(","), a.alert, a.review, a.data)
    # mtime=0: the same model gives the same bytes (and SHA-256)
    with open(a.out, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as fh:
        fh.write(json.dumps(d, separators=(",", ":")).encode())
    print(a.out, len(d["trees"]), "trees", sum(len(t["left"]) for t in d["trees"]), "nodes")
