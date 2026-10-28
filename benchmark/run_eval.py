"""Run the detectors on the benchmark datasets (build_datasets.py), offline, on the same files.

usage: python3 -I benchmark/run_eval.py aegis|guarddog|osv [--limit N] [--only DATASET] [--tag TAG] [--manifests SUFFIX]
  results/<tool>.jsonl   one line per item: dataset, group, name, version, verdict, rules, seconds (appended, resumable)
  --tag TAG              write results/<tool>-<TAG>.jsonl instead (e.g. aegis-behavior: the behavior analysis run, kept
                         apart from the frozen aegis.jsonl it is compared with)
  --manifests SUFFIX     read manifest-mal-SUFFIX.json / manifest-benign-SUFFIX.json (e.g. the held-out "eval" set)

Tools:
  aegis       the guard's code rules on the files (scan_engine.scan_local_file / scan_files; npm: install scripts too).
             No PyPI metadata, no OSV, no ML - the same inputs GuardDog gets for a local scan.
  guarddog   DataDog GuardDog 3.x on the same file / folder (local scan, no metadata rules, kernel sandbox on)
  osv        OSV lookup by name + version (MAL- records = known malicious; the "known ID lookup" baseline and the guard's
             intel layer). Most malicious samples here were reported to OSV, so this baseline is biased towards them.
Nothing is imported or run: the guard and GuardDog only read files.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Pool
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "guard"))
os.environ.setdefault("AEGIS_ML", "0")
BENCH = Path(os.environ.get("AEGIS_BENCH", str(REPO.parent / "research" / "bench")))
OUT = BENCH / "results"
GUARDDOG = BENCH / "gd-venv" / "bin" / "guarddog"


def items(only: str | None = None, suffix: str = "") -> list[dict]:
    out = []
    for part in ("mal", "benign"):
        p = BENCH / f"manifest-{part}{'-' + suffix if suffix else ''}.json"
        if not p.exists():
            continue
        for ds, rows in json.loads(p.read_text()).items():
            if isinstance(rows, list) and (only is None or ds == only):     # (a held-out manifest also lists
                out += [r for r in rows if isinstance(r, dict) and r.get("path") and not r.get("error")]  # its exclusions)
    return out


def _ecosystem(it: dict) -> str:
    return "npm" if it["dataset"] in ("dd-npm", "benign-npm") else "pypi"


# --------------------------------------------------------------------------------------------------------------- aegis

def _wheel_view(sample: Path, tmp: Path) -> list[Path] | None:
    """A Datadog compromised_lib sample is a copy of an installed site-packages folder: re-root it at the folder that
    holds the *.dist-info, the way the guard reads the real wheel."""
    dist = next((d for d in sample.rglob("*.dist-info") if d.is_dir()), None)
    if dist is None:
        return None
    view = tmp / f"{sample.parent.name}-0-py3-none-any.whl.unpacked"
    for p in dist.parent.rglob("*"):
        if p.is_file() and not p.is_symlink():
            q = view / p.relative_to(dist.parent)
            q.parent.mkdir(parents=True, exist_ok=True)
            os.link(p, q)
    return sorted(view.rglob("*"))


def aegis_one(it: dict) -> dict:
    import safe_extract
    import scan_engine as se
    from sources import npm
    t0 = time.time()
    path = Path(it["path"])
    try:
        with tempfile.TemporaryDirectory() as tmp:
            if _ecosystem(it) == "npm":
                if path.is_dir():
                    files = sorted(p for p in path.rglob("*"))
                else:
                    root = Path(tmp) / "pkg.tgz.unpacked"
                    root.mkdir()
                    safe_extract.extract_targz(path.read_bytes(), root, [], npm.KEEP_SUFFIXES)
                    files = sorted(root.rglob("*"))
                f = se.ScanFeatures(name=it["name"], version=it.get("version"), ecosystem="npm")
                f.install_time_files = npm.install_time_files(files)
                files += npm.write_lifecycle(files, Path(tmp), "pkg")
                v = se.scan_files(files, f)
            elif path.is_dir():
                files = (_wheel_view(path, Path(tmp)) if it.get("group") == "compromised_lib" else None) or sorted(path.rglob("*"))
                v = se.scan_files(files, se.ScanFeatures(name=it["name"], version=it.get("version")))
            else:
                v = se.scan_local_file(_real_file(path, Path(tmp)))
        rules = sorted({e["rule"] for e in v.features.evidence})
        f = v.features
        behavior = sorted({(e["rule"], e["phase"], e.get("action") or "-") for e in f.evidence if "phase" in e})
        return {**_key(it), "verdict": "UNREADABLE" if f.fetch_error else v.verdict, "score": round(v.score, 3), "rules": rules,
                "fetch_error": f.fetch_error, "seconds": round(time.time() - t0, 2),
                "behavior": [list(b) for b in behavior], "behavior_block": f.behavior_block,
                "behavior_review": f.behavior_review, "behavior_skipped": [list(x) for x in f.behavior_not_analyzed][:5],
                "reasons": [r for r in v.reasons if r.startswith("[hard rule]")][:4]}
    except Exception as e:
        return {**_key(it), "verdict": "ERROR", "error": repr(e)[:160], "seconds": round(time.time() - t0, 2)}


def _real_file(path: Path, tmp: Path) -> Path:
    """pypi_malregistry names some wheels (zip) ".tar.gz": link them under the name of what they are, for both tools."""
    if path.is_file() and path.name.endswith(".tar.gz"):
        with open(path, "rb") as fh:
            head = fh.read(2)
        if head == b"PK":
            fixed = tmp / (path.name[:-len(".tar.gz")] + ".whl")
            os.link(path, fixed)
            return fixed
    return path


def _key(it: dict) -> dict:
    return {k: it.get(k) for k in ("dataset", "group", "name", "version", "date")}


# ----------------------------------------------------------------------------------------------------------- guarddog

def guarddog_one(it: dict) -> dict:
    t0 = time.time()
    eco = _ecosystem(it)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            target = str(_real_file(Path(it["path"]), Path(tmp)))
            r = subprocess.run([str(GUARDDOG), eco, "scan", target, "--output-format=json"], capture_output=True, text=True,
                               timeout=600)
        doc = json.loads(r.stdout or "{}")
        res = doc.get("results") or {}
        threats = sorted(k for k, v in res.items() if v and not k.startswith("capability-"))
        risk = doc.get("risk_score") or {}
        return {**_key(it), "threats": threats, "issues": doc.get("issues"), "risk_label": risk.get("label"),
                "risk_score": risk.get("score"), "errors": (str(doc.get("errors"))[:200] if doc.get("errors") else None)
                or (r.stderr[-200:] if r.returncode not in (0, 1) else None), "seconds": round(time.time() - t0, 2)}
    except Exception as e:
        return {**_key(it), "threats": None, "error": repr(e)[:160], "seconds": round(time.time() - t0, 2)}


# ---------------------------------------------------------------------------------------------------------------- osv

def osv_all(its: list[dict]) -> list[dict]:
    import urllib.request
    out = []
    for i in range(0, len(its), 500):
        chunk = its[i:i + 500]
        body = {"queries": [{"package": {"name": it["name"], "ecosystem": "npm" if _ecosystem(it) == "npm" else "PyPI"},
                             **({"version": it["version"]} if it.get("version") else {})} for it in chunk]}
        req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.loads(r.read())["results"]
        for it, rr in zip(chunk, res):
            ids = [v["id"] for v in (rr or {}).get("vulns", [])]
            out.append({**_key(it), "mal_ids": [x for x in ids if x.startswith("MAL-")], "other_ids": [x for x in ids if not x.startswith("MAL-")]})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("tool", choices=["aegis", "guarddog", "osv"])
    ap.add_argument("--limit", type=int)
    ap.add_argument("--only")
    ap.add_argument("--tag", default="")
    ap.add_argument("--manifests", default="")
    a = ap.parse_args()
    OUT.mkdir(exist_ok=True)
    its = items(a.only, a.manifests)
    if a.limit:
        import random
        its = random.Random(1).sample(its, min(a.limit, len(its)))
    tag = "-".join(x for x in (a.tag, a.manifests) if x)
    out_path = OUT / f"{a.tool}{'-' + tag if tag else ''}{'-pilot' if a.limit else ''}.jsonl"
    if a.tool == "osv":
        rows = osv_all(its)
        out_path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
        print(f"osv: {len(rows)}")
        return 0
    done = set()
    if out_path.exists():
        done = {(r["dataset"], r["name"], r.get("version")) for r in map(json.loads, out_path.read_text().splitlines())}
    todo = [it for it in its if (it["dataset"], it["name"], it.get("version")) not in done]
    print(f"{a.tool}: {len(todo)} to do ({len(done)} already)", flush=True)
    with out_path.open("a") as fh:
        if a.tool == "aegis":
            with Pool(2, maxtasksperchild=50) as pool:
                for n, r in enumerate(pool.imap_unordered(aegis_one, todo, chunksize=2), 1):
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                    fh.flush()
                    if n % 200 == 0:
                        print(f"  {n}/{len(todo)}", flush=True)
        else:
            with ThreadPoolExecutor(2) as pool:
                for n, r in enumerate(pool.map(guarddog_one, todo), 1):
                    fh.write(json.dumps(r, ensure_ascii=False) + "\n")
                    fh.flush()
                    if n % 200 == 0:
                        print(f"  {n}/{len(todo)}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
