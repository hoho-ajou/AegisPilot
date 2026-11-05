"""
AegisPilot ML - random forest prediction and explanations with the Python standard library only.

    from forest import load
    f = load(path, sha256)                  # refuses a file whose SHA-256 differs, before it is parsed
    x = f.vector(raw)                       # raw feature dict -> model input (log1p, then float32 as scikit-learn)
    p = f.predict(x)                        # = model.predict_proba(X)[0, 1]
    base, phi = f.shap(x)                   # exact TreeSHAP (path-dependent), as shap.TreeExplainer on this forest

The JSON is made once by convert.py (needs scikit-learn). Each tree: left, right, feature, threshold, p1 (malicious
fraction at every node), cover (weighted_n_node_samples, used by TreeSHAP).

Important: scikit-learn casts X to float32 before walking the trees. vector() does the same; skipping it changes the
result for inputs near a split threshold.
Based on pure_forest.py (checked against scikit-learn and shap, 2026-11-02).
"""
import gzip
import hashlib
import io
import json
import math
import struct

FORMAT = "aegis-forest/2"
MAX_FILE_BYTES = 64 * 1024 * 1024        # the file as downloaded
MAX_JSON_BYTES = 64 * 1024 * 1024        # after gunzip: a small file must not inflate without bound
_F32 = struct.Struct("f")


class ModelError(Exception):
    """The model file is missing, too large, has another SHA-256, or is not a forest of this format."""


def f32(x):
    """Round a Python float to float32."""
    return _F32.unpack(_F32.pack(x))[0]


def _read_checked(path, sha256):
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError as e:
        raise ModelError(f"cannot read {path}: {type(e).__name__}")
    if len(data) > MAX_FILE_BYTES:
        raise ModelError(f"{path}: larger than {MAX_FILE_BYTES >> 20}MB")
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ModelError(f"{path}: SHA-256 differs from models.json")
    return data


def _gunzip(data):
    if data[:2] != b"\x1f\x8b":
        return data
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as g:
        while True:
            chunk = g.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
            if out.tell() > MAX_JSON_BYTES:
                raise ModelError(f"inflates to more than {MAX_JSON_BYTES >> 20}MB")
    return out.getvalue()


def load(path, sha256):
    """The forest in `path`, only after its bytes match `sha256` (from models.json)."""
    data = _read_checked(path, sha256)
    try:
        d = json.loads(_gunzip(data))
    except (OSError, EOFError, ValueError) as e:
        raise ModelError(f"{path}: not a readable model ({type(e).__name__})")
    return Forest(d)


class Forest:
    def __init__(self, d):
        try:
            if d.get("format") != FORMAT:
                raise ModelError(f"format {d.get('format')!r}, expected {FORMAT}")
            self.features = list(d["features"])
            self.log_features = set(d["log_features"])
            self.thresholds = {"alert": float(d["thresholds"]["alert"]), "review": float(d["thresholds"]["review"])}
            self.age_definition = d.get("age_definition")
            self.source = d.get("source", {})
            self.trees = [(t["left"], t["right"], t["feature"], t["threshold"], t["p1"], t["cover"]) for t in d["trees"]]
        except (KeyError, TypeError, AttributeError) as e:
            raise ModelError(f"not a forest of format {FORMAT} ({type(e).__name__}: {e})")
        if not self.trees:
            raise ModelError("no trees")
        self.base = sum(t[4][0] for t in self.trees) / len(self.trees)

    def vector(self, raw):
        return [f32(math.log1p(raw[f]) if f in self.log_features else float(raw[f])) for f in self.features]

    def predict(self, x):
        s = 0.0
        for left, right, feat, thr, p1, _ in self.trees:
            n = 0
            while left[n] != -1:
                n = left[n] if x[feat[n]] <= thr[n] else right[n]
            s += p1[n]
        return s / len(self.trees)

    def shap(self, x):
        """Exact TreeSHAP (Lundberg et al. 2018, Algorithm 2), averaged over the trees.
        base + sum(phi) == predict(x) up to float rounding."""
        phi = [0.0] * len(self.features)
        for tree in self.trees:
            _tree_shap(tree, x, phi)
        k = len(self.trees)
        return self.base, [p / k for p in phi]


def _extend(path, pz, po, pi):
    path = [e[:] for e in path]
    l = len(path)
    path.append([pi, pz, po, 1.0 if l == 0 else 0.0])
    for i in range(l - 1, -1, -1):
        path[i + 1][3] += po * path[i][3] * (i + 1) / (l + 1)
        path[i][3] = pz * path[i][3] * (l - i) / (l + 1)
    return path


def _unwind(path, i):
    path = [e[:] for e in path]
    l = len(path) - 1
    n = path[l][3]
    z, o = path[i][1], path[i][2]
    for j in range(l - 1, -1, -1):
        if o != 0:
            tmp = path[j][3]
            path[j][3] = n * (l + 1) / ((j + 1) * o)
            n = tmp - path[j][3] * z * (l - j) / (l + 1)
        else:
            path[j][3] = path[j][3] * (l + 1) / (z * (l - j))
    for j in range(i, l):
        path[j][0], path[j][1], path[j][2] = path[j + 1][0], path[j + 1][1], path[j + 1][2]
    path.pop()
    return path


def _unwound_sum(path, i):
    l = len(path) - 1
    z, o = path[i][1], path[i][2]
    total, n = 0.0, path[l][3]
    for j in range(l - 1, -1, -1):
        if o != 0:
            tmp = n * (l + 1) / ((j + 1) * o)
            total += tmp
            n = path[j][3] - tmp * z * (l - j) / (l + 1)
        else:
            total += path[j][3] / (z * (l - j) / (l + 1))
    return total


def _tree_shap(tree, x, phi):
    L, R, Fe, T, V, W = tree

    def recurse(j, path, pz, po, pi):
        path = _extend(path, pz, po, pi)
        if L[j] == -1:
            for i in range(1, len(path)):
                phi[path[i][0]] += _unwound_sum(path, i) * (path[i][2] - path[i][1]) * V[j]
            return
        f = Fe[j]
        hot, cold = (L[j], R[j]) if x[f] <= T[j] else (R[j], L[j])
        iz = io_ = 1.0
        k = next((i for i in range(1, len(path)) if path[i][0] == f), None)
        if k is not None:
            iz, io_ = path[k][1], path[k][2]
            path = _unwind(path, k)
        recurse(hot, path, iz * W[hot] / W[j], io_, f)
        recurse(cold, path, iz * W[cold] / W[j], 0.0, f)

    recurse(0, [], 1.0, 1.0, -1)
