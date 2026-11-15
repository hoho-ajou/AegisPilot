"""Shared helpers of the npm model training (training/npm). Not part of the guard: run on a machine with network access.

The feature code is the guard's own (guard/ml/npm_features.py, js_code_features.py), imported from the checkout, so the
training data and the guard compute every feature the same way.
"""
import datetime
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ML = REPO / "guard" / "ml"
if str(ML) not in sys.path:
    sys.path.insert(0, str(ML))

import npm_features as NF          # noqa: E402,F401
import js_code_features as JS      # noqa: E402,F401

DATA = Path(os.environ.get("AEGIS_NPM_DATA", str(REPO.parent / "research" / "npm-ml")))
INSTALL_AGES = (0, 1, 3, 7, 14, 30)      # days after a version is published that it may be installed (as for PyPI R3f)
UTC = datetime.timezone.utc


def now_utc():
    return datetime.datetime.now(UTC)


def iso(t):
    return t.astimezone(UTC).isoformat().replace("+00:00", "Z") if t else None


def parse_t(s):
    if not s:
        return None
    t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def excluded_names(manifests):
    """npm package names in benchmark manifests (benchmark/build_datasets.py): kept out of training so the benchmark
    stays an independent measurement."""
    out = set()
    for p in manifests or ():
        man = json.loads(Path(p).read_text())
        for ds, rows in man.items():
            if "npm" not in ds or not isinstance(rows, list):
                continue
            for r in rows:
                if isinstance(r, dict) and r.get("name"):
                    out.add(str(r["name"]).lower())
    return out


def trim_packument(doc):
    """The part of a registry document the features read (time, maintainers), plus names for the record."""
    return {k: doc.get(k) for k in ("name", "dist-tags", "time", "maintainers") if k in doc}
