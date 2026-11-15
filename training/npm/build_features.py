"""
Features of the npm training data, one JSON line per package version (input of train.py).

    python3 build_features.py malicious --datadog <clone> --out mal.jsonl [--exclude-manifests M1 M2 ...]
    python3 build_features.py benign --benign <collect_benign.py folder> --out benign.jsonl
    python3 build_features.py local --node-modules DIR [DIR ...] --out local.jsonl      # smoke test, no registry data

Samples are read as data: zips and tarballs are opened in memory (js_code_features.iter_archive), nothing is extracted
to disk or run. Each line:
  label 1/0, kind (malicious_intent / compromised_lib / top / longtail / new / local), name, version,
  t_scan (when the package was found / collected), t_published (this version), t_created (the package),
  raw (every feature of npm_full at t_scan; registry ones only when registry_ok), registry_ok, source (file).
train.py recomputes age_days for other install times from t_published and t_created.
"""
import argparse
import json
import multiprocessing as mp
import re
import signal
import sys
import time
from pathlib import Path

from common import NF, JS, excluded_names, iso, parse_t, now_utc

TIMEOUT = 300           # seconds per sample (pure-Python zip decryption of a 80MB sample takes about a minute)


class _Timeout(Exception):
    pass


def _alarm(*_):
    raise _Timeout()


def _times(doc, version):
    t = (doc or {}).get("time") or {}
    try:
        pub = parse_t(t.get(version))
    except ValueError:
        pub = None
    try:
        created = parse_t(t.get("created"))
    except ValueError:
        created = None
    return pub, created


def _row(label, kind, path, data, doc, version, t_scan):
    r = NF.compute(JS.iter_archive(data), doc, version, t_scan)
    pub, created = _times(doc, r["version"])
    return {"label": label, "kind": kind, "name": r["name"], "version": r["version"], "t_scan": iso(t_scan),
            "t_published": iso(pub), "t_created": iso(created), "registry_ok": r["registry_ok"], "raw": r["raw"],
            "source": str(path)}


def _malicious(task):
    path, kind, version = task
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(TIMEOUT)
    try:
        data = Path(path).read_bytes()
        doc = NF.sample_packument(data)
        return _row(1, kind, path, data, doc, version, NF.found_at(path))
    except _Timeout:
        return {"error": "timeout", "source": path}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:120]}", "source": path}
    finally:
        signal.alarm(0)


def _benign(task):
    tgz, kind = task
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(TIMEOUT)
    try:
        side = json.loads(Path(str(tgz)[:-4] + ".json").read_text())       # written by collect_benign.py
        data = Path(tgz).read_bytes()
        return _row(0, kind, tgz, data, side.get("packument"), side["version"], parse_t(side["collected_at"]))
    except _Timeout:
        return {"error": "timeout", "source": str(tgz)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:120]}", "source": str(tgz)}
    finally:
        signal.alarm(0)


def _local(pkg_dir):
    try:
        r = NF.compute(JS.iter_dir(pkg_dir), None, None, now_utc())
        return {"label": 0, "kind": "local", "name": r["name"], "version": r["version"], "t_scan": iso(now_utc()),
                "t_published": None, "t_created": None, "registry_ok": False, "raw": r["raw"], "source": str(pkg_dir)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:120]}", "source": str(pkg_dir)}


def malicious_tasks(clone, exclude):
    root = Path(clone) / "samples" / "npm"
    tasks, skipped = [], 0
    for z in sorted(root.glob("*/**/*.zip")):
        rel = z.relative_to(root).parts               # kind / name / version / file.zip
        if len(rel) < 4:
            continue
        kind, name, version = rel[0], rel[1], rel[2]
        if name.startswith("@"):                      # "@scope@name" in the dataset
            name = "@" + name[1:].replace("@", "/", 1)
        if name.lower() in exclude:
            skipped += 1
            continue
        tasks.append((str(z), kind, version))
    return tasks, skipped


def run(fn, tasks, out, workers):
    n_ok = n_err = 0
    t0 = time.time()
    with open(out, "w", encoding="utf-8") as fh, mp.Pool(workers, maxtasksperchild=50) as pool:
        for i, row in enumerate(pool.imap_unordered(fn, tasks, chunksize=4), 1):
            if "error" in row:
                n_err += 1
                print("  skip:", row["source"], row["error"], file=sys.stderr)
                fh.write(json.dumps({"skipped": row}) + "\n")
            else:
                n_ok += 1
                fh.write(json.dumps(row) + "\n")
            if i % 500 == 0:
                print(f"  {i}/{len(tasks)}  {time.time() - t0:.0f}s", file=sys.stderr)
    print(f"{out}: {n_ok} rows, {n_err} skipped, {time.time() - t0:.0f}s")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=["malicious", "benign", "local"])
    ap.add_argument("--datadog", help="clone of DataDog/malicious-software-packages-dataset (samples/npm checked out)")
    ap.add_argument("--benign", help="folder written by collect_benign.py")
    ap.add_argument("--node-modules", nargs="*", default=[], help="node_modules folders (smoke test only)")
    ap.add_argument("--exclude-manifests", nargs="*", default=[], help="benchmark manifests whose npm names stay out")
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 1))
    a = ap.parse_args()
    exclude = excluded_names(a.exclude_manifests)
    if a.what == "malicious":
        tasks, skipped = malicious_tasks(a.datadog, exclude)
        print(f"malicious: {len(tasks)} samples ({skipped} left out: in the benchmark manifests)")
        run(_malicious, tasks, a.out, a.workers)
    elif a.what == "benign":
        tasks = []
        for tgz in sorted(Path(a.benign).glob("*/*.tgz")):
            if Path(str(tgz)[:-4] + ".json").exists():
                tasks.append((str(tgz), tgz.parent.name))
        print(f"benign: {len(tasks)} packages")
        run(_benign, tasks, a.out, a.workers)
    else:
        seen, dirs = set(), []
        for nm in a.node_modules:
            for pj in sorted(Path(nm).rglob("package.json")):
                d = pj.parent
                if d.parent.name != "node_modules" and not (d.parent.name.startswith("@") and d.parent.parent.name == "node_modules"):
                    continue
                try:
                    doc = json.loads(pj.read_text(encoding="utf-8-sig"))
                except (ValueError, OSError):
                    continue
                key = (doc.get("name"), doc.get("version"))
                if not key[0] or key in seen or re.search(r"[\\/]test", str(d)):
                    continue
                seen.add(key)
                dirs.append(str(d))
        print(f"local: {len(dirs)} packages")
        run(_local, dirs, a.out, a.workers)


if __name__ == "__main__":
    main()
