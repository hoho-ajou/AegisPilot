"""Criteria 4 (name problems) and 7 (latency), through the real decision (guard_core.check_command,
auto mode, fresh HOME, network on: PyPI + OSV as in an install).

usage: python3 -I benchmark/names_latency_eval.py names|latency OUT.json
  names    (a) hallucinated names: plausible package names an agent might invent (popular tokens joined), kept only if
               PyPI has no such project -> expected REVIEW ("name not on PyPI")
           (b) typosquats: names from the malicious datasets within edit distance 2 of a top-5,000 PyPI name (not the
               guard's own popular list) -> the guard's name check (typosquat_check) on the name alone
  latency  `pip install <name>==<version>` for a seeded sample of the benchmark's top / longtail / new packages:
           seconds per command, p50 / p95 by group and by file size
"""
from __future__ import annotations

import json
import os
import random
import re
import statistics
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "guard"))
os.environ.update({"AASM_ML": "0", "AASM_MODE": "auto", "HOME": tempfile.mkdtemp()})
BENCH = Path(os.environ.get("AASM_BENCH", str(REPO.parent / "research" / "bench")))
SEED = 20261023
TOKENS = ["fast", "py", "easy", "auto", "smart", "simple", "json", "http", "async", "data", "ml", "ai", "llm", "agent",
          "vector", "pdf", "csv", "yaml", "config", "utils", "tools", "client", "sdk", "api", "parser", "db", "cache",
          "graph", "rag", "embed", "token", "chat", "prompt", "vision", "audio", "web", "scrape", "log", "secure", "env"]


def _exists(name: str) -> bool:
    try:
        urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=20).close()
        return True
    except urllib.error.HTTPError as e:
        return e.code != 404
    except Exception:
        return True                                   # unknown: do not count it as a hallucination


def _dist(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def names(out: Path) -> None:
    import guard_core
    import scan_engine as se
    guard_core.check_integrity = lambda: []
    rnd = random.Random(SEED)
    halluc = []
    while len(halluc) < 60:
        n = "-".join(rnd.sample(TOKENS, 2)) if rnd.random() < 0.5 else rnd.choice(TOKENS) + rnd.choice(TOKENS)
        if n not in halluc and not _exists(n):
            halluc.append(n)
    rows = []
    with tempfile.TemporaryDirectory() as d:
        for n in halluc:
            r = guard_core.check_command(f"pip install {n}", d)
            rec = json.loads(Path(d, ".aasm", "last_review.json").read_text())["packages"][0]
            rows.append({"kind": "hallucinated", "name": n, "action": r.action, "verdict": rec["verdict"],
                         "failure_kind": (rec.get("coverage") or {}).get("failure_kind")})
    top = [r["project"] for r in json.loads(urllib.request.urlopen(
        "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json", timeout=60).read())["rows"][:5000]]
    top_n = {re.sub(r"[-_.]+", "-", t).lower() for t in top}
    mal_names = set()
    for part in ("mal",):
        man = json.loads((BENCH / f"manifest-{part}.json").read_text())
        for ds in ("dd-pypi", "malregistry"):
            mal_names |= {r["name"] for r in man.get(ds, [])}
    squats = []
    for n in sorted(mal_names):
        k = re.sub(r"[-_.]+", "-", n).lower()
        if k in top_n:
            continue
        near = next((t for t in top_n if 0 < _dist(k, t, 2) <= 2), None)
        if near:
            squats.append((n, near))
    for n, near in squats:
        f = se.ScanFeatures(name=n, version=None)
        se.typosquat_check(n, f)
        d = f.min_edit_distance                       # the guard's own criterion: distance 1-2 to a name on its list
        rows.append({"kind": "typosquat", "name": n, "near": near, "flagged": d is not None and 0 < d <= 2,
                     "guard_near": f.closest_popular_name, "distance": d})
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1))
    h = [r for r in rows if r["kind"] == "hallucinated"]
    t = [r for r in rows if r["kind"] == "typosquat"]
    print("hallucinated", len(h), {v: sum(r["verdict"] == v for r in h) for v in ("ALLOW", "NEEDS_HUMAN_REVIEW", "BLOCK")})
    print("typosquat", len(t), "flagged", sum(r["flagged"] for r in t))


def latency(out: Path, n_per_group: int = 40) -> None:
    import guard_core
    guard_core.check_integrity = lambda: []
    man = json.loads((BENCH / "manifest-benign.json").read_text())
    rnd = random.Random(SEED)
    rows = []
    for group in ("top", "longtail", "new"):
        pool = [r for r in man["benign-pypi"] if r["group"] == group and r.get("path")]
        for it in rnd.sample(pool, min(n_per_group, len(pool))):
            with tempfile.TemporaryDirectory() as d:
                t0 = time.time()
                r = guard_core.check_command(f"pip install {it['name']}=={it['version']}", d)
                rows.append({"group": group, "name": it["name"], "version": it["version"], "size": it.get("size"),
                             "seconds": round(time.time() - t0, 2), "action": r.action})
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1))
    for group in ("top", "longtail", "new", None):
        s = sorted(r["seconds"] for r in rows if group is None or r["group"] == group)
        print(group or "all", len(s), "p50", statistics.median(s), "p95", s[int(len(s) * 0.95) - 1], "max", s[-1])


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("names", "latency"):
        print(__doc__)
        sys.exit(0 if sys.argv[1:2] in (["-h"], ["--help"]) else 2)
    {"names": names, "latency": latency}[sys.argv[1]](Path(sys.argv[2]))
    os._exit(0)
