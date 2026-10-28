"""Benchmark datasets for criteria 1, 2 and 7 (detection, false positives, latency). Everything is downloaded OUTSIDE
the repository, to the folder named by AEGIS_BENCH (default: ../research/bench next to the repository), and only read:
archives are unpacked as files, nothing is imported, built or run. The malicious samples are real malware source - keep
them on an isolated machine, never in git.

usage: python3 -I benchmark/build_datasets.py [mal|benign|all]
       python3 -I benchmark/build_datasets.py mal|benign --suffix eval --seed 20261024 --exclude manifest-mal.json manifest-benign.json
                                 [--top-ranks 1001-5000]
  --suffix S     write manifest-<part>-S.json (a second, held-out set; run_eval.py --manifests S reads it)
  --seed N       sampling seed (the development set used 20261023)
  --exclude F..  manifests whose packages are left out (by name, per ecosystem): the held-out set shares nothing with them
  --top-ranks    benign PyPI from this download-rank range of top-pypi-packages instead of top/longtail/new
  In held-out mode the malicious part is malregistry (MALREG_SAMPLE of the packages not in the excluded manifests) and
  Datadog npm (NPM_SAMPLE not in them); Datadog PyPI was used whole by the development set.

  mal/dd-pypi/<kind>/<name>/sample.unpacked   Datadog malicious-software-packages-dataset, PyPI, one version per package,
                                               without the samples looked at while tuning the rules
                                               (optional local lists, see seen_samples)
  mal/dd-npm/<kind>/<name>/sample.unpacked    the same dataset, npm, a seeded sample of NPM_SAMPLE packages
  mal/malregistry/<name>/<file>               lxyeternal/pypi_malregistry (never used before), one archive per package,
                                               a seeded sample of MALREG_SAMPLE, minus names already in dd-pypi
  benign/pypi/<group>/<name>@<version>/<file> the release file pip would install (artifact_select), <= MAX_BYTES:
                                               top (top-pypi-packages, 30 days), longtail (random from the simple index),
                                               new (projects created in the last days, PyPI changelog)
  benign/npm/<name>@<version>.tgz             popular npm packages (optional local name list + registry search by
                                               popularity)
  manifest-<part>.json                        every item: dataset, group, name, version, path, sha256, date, errors
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import random
import re
import subprocess
import sys
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "guard"))
BENCH = Path(os.environ.get("AEGIS_BENCH", str(REPO.parent / "research" / "bench")))
SEED = 20261023
NPM_SAMPLE = 600
MALREG_SAMPLE = 2000
BENIGN_PER_GROUP = 1000
NPM_BENIGN = 500
MAX_BYTES = 50 * 1024 * 1024
UA = {"User-Agent": "aegis-benchmark (research)"}


def _get(url: str, timeout: int = 60, limit: int | None = None) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read(limit + 1 if limit else -1)


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _readonly(d: Path) -> None:
    for p in d.rglob("*"):
        if p.is_file():
            p.chmod(0o444)


def _unzip(zpath: Path, dest: Path) -> None:
    """A Datadog sample (zip, password "infected") into dest, no path escapes."""
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zpath) as z:
        z.pwd = b"infected"
        for m in z.infolist():
            p = (dest / m.filename).resolve()
            if m.is_dir() or not str(p).startswith(str(dest.resolve())):
                continue
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(z.read(m))


# ------------------------------------------------------------------------------------------------------- malicious

def seen_samples() -> dict[str, set]:
    """Datadog samples looked at while writing or tuning the rules: excluded from the holdout. The lists are optional files
    in $AEGIS_BENCH/seen/ (not distributed); a missing list is skipped with one line on stdout."""
    intent, compromised = set(), set()
    for f in ("malicious_dev.json", "malicious_holdout.json", "malicious_holdout2.json"):
        src = BENCH / "seen" / f
        if not src.exists():
            print(f"seen samples: {src} not found, exclusion skipped")
            continue
        intent |= {s["name"] for s in json.loads(src.read_text())}
    src = BENCH / "seen" / "chain_order_mal.json"
    if src.exists():
        for r in json.loads(src.read_text()):
            (intent if r["kind"] == "intent" else compromised).add(r["name"])
    else:
        print(f"seen samples: {src} not found, exclusion skipped")
    return {"malicious_intent": intent, "compromised_lib": compromised}


def _dd_paths(eco: str) -> list[str]:
    repo = BENCH / "datadog"
    out = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD", f"samples/{eco}"],
                         capture_output=True, text=True, check=True).stdout.split("\n")
    return [p for p in out if p.endswith(".zip")]


def _dd_pick(paths: list[str]) -> dict[tuple, str]:
    """(kind, name) -> the newest sample path (one version per package)."""
    best: dict[tuple, str] = {}
    for p in paths:
        _, _, kind, name = p.split("/")[:4]
        if (kind, name) not in best or Path(p).name > Path(best[(kind, name)]).name:
            best[(kind, name)] = p
    return best


def _dd_checkout(paths: list[str]) -> None:
    repo = BENCH / "datadog"
    for i in range(0, len(paths), 200):
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), "checkout", "-q", "HEAD", "--", *paths[i:i + 200]],
                       check=True, timeout=1800)


def build_dd(eco: str, sample: int | None, seed: int = SEED, exclude: set | None = None) -> list[dict]:
    picked = _dd_pick(_dd_paths(eco))
    seen = seen_samples() if eco == "pypi" else {"malicious_intent": set(), "compromised_lib": set()}
    keys = sorted(k for k in picked if k[1] not in seen.get(k[0], set()) and _norm(k[1]) not in (exclude or set()))
    excluded = len(picked) - len(keys)
    if sample:
        rnd = random.Random(seed)
        keys = sorted(rnd.sample(keys, min(sample, len(keys))))
    todo = [picked[k] for k in keys if not (BENCH / "mal" / f"dd-{eco}" / k[0] / k[1] / "sample.unpacked").exists()]
    _dd_checkout(todo)
    rows = []
    for kind, name in keys:
        rel = picked[(kind, name)]
        d = BENCH / "mal" / f"dd-{eco}" / kind / name
        z = BENCH / "datadog" / rel
        row = {"dataset": f"dd-{eco}", "group": kind, "name": name, "version": rel.split("/")[4],
               "date": Path(rel).name[:10], "path": str(d / "sample.unpacked"), "source": rel}
        try:
            if not (d / "sample.unpacked").exists():
                _unzip(z, d / "sample.unpacked")
                _readonly(d / "sample.unpacked")
            row["sha256"] = _sha(z) if z.exists() else None
        except Exception as e:
            row["error"] = repr(e)[:160]
        rows.append(row)
    print(f"dd-{eco}: {len(rows)} (excluded as seen in development: {excluded})")
    return rows


def build_malregistry(skip_names: set, seed: int = SEED) -> list[dict]:
    root = BENCH / "malregistry"
    per_pkg: dict[str, Path] = {}
    for p in sorted(root.glob("*/*/*")):
        if p.is_file() and p.name.endswith((".tar.gz", ".whl", ".zip")) and ".git" not in p.parts:
            per_pkg.setdefault(p.parts[len(root.parts)], p)     # first version of each package
    names = sorted(n for n in per_pkg if _norm(n) not in skip_names)
    rnd = random.Random(seed)
    names = sorted(rnd.sample(names, min(MALREG_SAMPLE, len(names))))
    rows = [{"dataset": "malregistry", "group": "malicious", "name": n, "version": per_pkg[n].parent.name,
             "date": None, "path": str(per_pkg[n]), "sha256": _sha(per_pkg[n])} for n in names]
    print(f"malregistry: {len(rows)} of {len(per_pkg)} packages (minus {len(per_pkg) - len(names) - 0} overlapping/unsampled)")
    return rows


# ---------------------------------------------------------------------------------------------------------- benign

def _pypi_release_file(name: str, group: str) -> dict:
    import artifact_select
    from sources import pypi
    row = {"dataset": "benign-pypi", "group": group, "name": name}
    try:
        meta = pypi.metadata(name)
        ver = meta["info"]["version"]
        files = [f for f in meta["releases"].get(ver) or [] if not f.get("yanked")]
        if not files:
            raise ValueError("no files in the latest release")
        chosen, kind, _ = artifact_select.choose(files, "installed")
        fname = os.path.basename(chosen["filename"])
        row.update(version=ver, file=fname, size=chosen.get("size"),
                   date=min(f["upload_time_iso_8601"][:10] for f in files))
        dest = BENCH / "benign" / "pypi" / group / f"{name}@{ver}" / fname
        if (chosen.get("size") or 0) > MAX_BYTES:
            row["skipped"] = f"larger than {MAX_BYTES >> 20}MB"
            return row
        if not dest.exists():
            raw = _get(chosen["url"], 120, MAX_BYTES)
            if len(raw) > MAX_BYTES:
                row["skipped"] = f"larger than {MAX_BYTES >> 20}MB"
                return row
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
        row.update(path=str(dest), sha256=_sha(dest))
    except Exception as e:
        row["error"] = repr(e)[:160]
    return row


def top_names(n: int) -> list[str]:
    doc = json.loads(_get("https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"))
    return [r["project"] for r in doc["rows"][:n]]


def longtail_names(n: int, exclude: set) -> list[str]:
    req = urllib.request.Request("https://pypi.org/simple/", headers={**UA, "Accept": "application/vnd.pypi.simple.v1+json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        names = [p["name"] for p in json.loads(r.read())["projects"]]
    rnd = random.Random(SEED)
    pool = [x for x in rnd.sample(names, n * 3) if _norm(x) not in exclude]
    return pool[: n * 2]                 # extra: some have no files; the first n that download are kept


def new_names(n: int, exclude: set) -> list[str]:
    """Projects created recently (PyPI changelog "create" actions), newest first."""
    import xmlrpc.client
    c = xmlrpc.client.ServerProxy("https://pypi.org/pypi")
    last = c.changelog_last_serial()
    out, seen, serial = [], set(), last
    while len(out) < n * 2 and last - serial < 400_000:
        serial -= 20_000
        for name, _ver, _ts, action, _s in c.changelog_since_serial(serial)[:20_000]:
            if action == "create" and _norm(name) not in seen and _norm(name) not in exclude:
                seen.add(_norm(name))
                out.append(name)
        time.sleep(1)
    return out[: n * 2]


def build_benign_pypi() -> list[dict]:
    rows, taken = [], set()
    for group, names in (("top", top_names(BENIGN_PER_GROUP)), ):
        rows += _download_group(group, names, BENIGN_PER_GROUP)
    taken = {_norm(r["name"]) for r in rows}
    rows += _download_group("longtail", longtail_names(BENIGN_PER_GROUP, taken), BENIGN_PER_GROUP)
    taken = {_norm(r["name"]) for r in rows}
    rows += _download_group("new", new_names(BENIGN_PER_GROUP, taken), BENIGN_PER_GROUP)
    return rows


def _download_group(group: str, names: list[str], want: int) -> list[dict]:
    with ThreadPoolExecutor(8) as pool:
        got = list(pool.map(lambda n: _pypi_release_file(n, group), names))
    ok = [r for r in got if r.get("path")][:want]
    rest = [r for r in got if not r.get("path")]
    print(f"benign-pypi/{group}: {len(ok)} files ({sum('skipped' in r for r in rest)} too large, "
          f"{sum('error' in r for r in rest)} errors, {len(names)} names tried)")
    return ok + [r for r in rest if group == "top"]      # top: keep the skipped ones listed (coverage is reported)


def build_benign_rank_range(lo: int, hi: int, n: int, exclude: set, seed: int) -> list[dict]:
    """Benign PyPI from download ranks lo..hi of top-pypi-packages (a range the development set did not sample)."""
    names = [x for x in top_names(hi)[lo - 1:hi] if _norm(x) not in exclude]
    rnd = random.Random(seed)
    names = rnd.sample(names, min(len(names), int(n * 1.3)))
    return _download_group(f"rank{lo}-{hi}", names, n)


NPM_QUERIES = ("react", "vue", "angular", "node", "cli", "test", "lint", "build", "http", "util", "types", "aws", "parser",
               "logger", "database", "css", "date", "config", "auth", "stream")
NPM_QUERIES_HELDOUT = ("express", "webpack", "babel", "eslint", "graphql", "redux", "jest", "axios", "markdown", "image",
                       "crypto", "server", "router", "color", "file", "json", "string", "array", "promise", "plugin",
                       "svg", "chart", "form", "socket", "sql")


def build_benign_npm(exclude: set | None = None, queries: tuple = NPM_QUERIES, base_list: bool = True) -> list[dict]:
    from sources import npm
    names = []
    if base_list:
        src = BENCH / "npm_names.txt"                        # optional list of popular npm names (not distributed)
        if src.exists():
            names = src.read_text().split()
        else:
            print(f"benign-npm: {src} not found, using registry search only")
    for q in queries:
        try:
            doc = json.loads(_get(f"https://registry.npmjs.org/-/v1/search?text={q}&size=100&popularity=1.0&quality=0.0&maintenance=0.0"))
            names += [o["package"]["name"] for o in doc["objects"]]
        except Exception:
            pass
    names = [x for x in dict.fromkeys(names) if x.lower() not in (exclude or set())][:NPM_BENIGN]

    def one(name):
        row = {"dataset": "benign-npm", "group": "popular", "name": name}
        try:
            meta = npm.metadata(name)
            ver = npm.pick_version(meta, None)
            dist = meta["versions"][ver]["dist"]
            dest = BENCH / "benign" / "npm" / f"{name.replace('/', '__')}@{ver}.tgz"
            if not dest.exists():
                raw = _get(dist["tarball"], 120, MAX_BYTES)
                if len(raw) > MAX_BYTES:
                    row["skipped"] = "too large"
                    return row
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(raw)
            row.update(version=ver, path=str(dest), sha256=_sha(dest))
        except Exception as e:
            row["error"] = repr(e)[:160]
        return row
    with ThreadPoolExecutor(8) as pool:
        rows = list(pool.map(one, names))
    print(f"benign-npm: {sum(1 for r in rows if r.get('path'))} of {len(names)}")
    return rows


def _excluded(paths: list[str]) -> tuple[set, set]:
    """(PyPI names, npm names) of the packages in the given manifests (normalized)."""
    pypi, npm_ = set(), set()
    for p in paths:
        doc = json.loads((BENCH / p if not os.path.isabs(p) else Path(p)).read_text())
        for ds, rows in doc.items():
            if isinstance(rows, list):
                for r in rows:
                    (npm_ if "npm" in ds else pypi).add(_norm(r["name"]) if "npm" not in ds else r["name"].lower())
    return pypi, npm_


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("what", nargs="?", default="all", choices=["mal", "benign", "all"])
    ap.add_argument("--suffix", default="")
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--exclude", nargs="*", default=[])
    ap.add_argument("--top-ranks", default="")
    a = ap.parse_args()
    what = a.what
    if a.suffix:                                          # a held-out set: never mixes with the development manifests
        if not a.exclude or a.seed == SEED:
            ap.error("--suffix needs --exclude (the development manifests) and a different --seed")
        ex_pypi, ex_npm = _excluded(a.exclude)
        man_path = BENCH / f"manifest-{what}-{a.suffix}.json"
        man = json.loads(man_path.read_text()) if man_path.exists() else {}
        if what in ("mal", "all"):
            man["dd-npm"] = build_dd("npm", NPM_SAMPLE, a.seed, ex_npm)
            dd_pypi_names = {_norm(k[1]) for k in _dd_pick(_dd_paths("pypi"))}
            man["malregistry"] = build_malregistry(ex_pypi | dd_pypi_names, a.seed)
        if what in ("benign", "all"):
            lo, hi = (int(x) for x in (a.top_ranks or "1001-5000").split("-"))
            man["benign-pypi"] = build_benign_rank_range(lo, hi, BENIGN_PER_GROUP, ex_pypi, a.seed)
            man["benign-npm"] = build_benign_npm(ex_npm, NPM_QUERIES_HELDOUT, base_list=False)
        man["seed"], man["excluded"] = a.seed, a.exclude
        man["frozen_at"] = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%h %ci"], capture_output=True,
                                          text=True).stdout.strip()
        man_path.write_text(json.dumps(man, ensure_ascii=False, indent=1))
        return 0
    man_path = BENCH / f"manifest-{what}.json"            # one file per part: the parts can run side by side
    man = json.loads(man_path.read_text()) if man_path.exists() else {}
    if what in ("mal", "all"):
        man["dd-pypi"] = build_dd("pypi", None)
        man["dd-npm"] = build_dd("npm", NPM_SAMPLE)
        man["malregistry"] = build_malregistry({_norm(r["name"]) for r in man["dd-pypi"]})
    if what in ("benign", "all"):
        man["benign-pypi"] = build_benign_pypi()
        man["benign-npm"] = build_benign_npm()
    man["frozen_at"] = subprocess.run(["git", "-C", str(REPO), "log", "-1", "--format=%h %ci"], capture_output=True,
                                      text=True).stdout.strip()
    man_path.write_text(json.dumps(man, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
