"""Criterion 3 (vulnerable versions): does the guard stop vulnerable releases by severity, and is the version it proposes
really fixed? Sample: OSV's PyPI advisories (all.zip, downloaded to the bench folder) with CRITICAL / HIGH severity,
one affected release each (the newest release the advisory lists as affected that PyPI still serves).

usage: python3 -I benchmark/vuln_eval.py N_PER_SEVERITY OUT.json
  per item: package, version, advisory, severity, guard verdict, proposed fix version, and whether OSV still lists any
  advisory for (package, proposed version) with the same ids ("proposal still vulnerable")
The guard runs as in a real install (scan_engine.scan_package: PyPI + OSV, ML off); nothing is installed or run.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "guard"))
os.environ.setdefault("AEGIS_ML", "0")
BENCH = Path(os.environ.get("AEGIS_BENCH", str(REPO.parent / "research" / "bench")))
SEED = 20261023


def candidates() -> dict[str, list]:
    z = zipfile.ZipFile(BENCH / "osv-pypi-all.zip")
    out: dict[str, list] = {"CRITICAL": [], "HIGH": []}
    for name in z.namelist():
        d = json.loads(z.read(name))
        sev = (d.get("database_specific") or {}).get("severity")
        if sev not in out or d.get("withdrawn"):
            continue
        for a in d.get("affected", []):
            pkg = (a.get("package") or {})
            if pkg.get("ecosystem") != "PyPI" or not a.get("versions"):
                continue
            out[sev].append({"advisory": d["id"], "aliases": d.get("aliases", []), "package": pkg["name"],
                             "severity": sev, "affected": a["versions"]})
    return out


def pick_version(c: dict) -> str | None:
    from sources import pypi
    try:
        rel = pypi.metadata(c["package"]).get("releases") or {}
    except Exception:
        return None
    served = [v for v in c["affected"] if rel.get(v) and not all(f.get("yanked") for f in rel[v])]
    return served[-1] if served else None            # OSV lists versions in order; the newest still served


def osv_ids(pkg: str, ver: str) -> set:
    body = json.dumps({"package": {"name": pkg, "ecosystem": "PyPI"}, "version": ver}).encode()
    req = urllib.request.Request("https://api.osv.dev/v1/query", data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        vulns = json.loads(r.read()).get("vulns", [])
    return {v["id"] for v in vulns} | {a for v in vulns for a in v.get("aliases", [])}


def one(c: dict) -> dict:
    import scan_engine as se
    row = {k: c[k] for k in ("advisory", "package", "severity")}
    ver = pick_version(c)
    if not ver:
        return {**row, "skipped": "no affected release still on PyPI"}
    row["version"] = ver
    t0 = time.time()
    v = se.scan_package(c["package"], ver)
    row.update(verdict=v.verdict, seconds=round(time.time() - t0, 1), fetch_error=v.features.fetch_error,
               osv_max_severity=v.features.osv_max_severity, found=c["advisory"] in {x.get("id") for x in v.features.osv_vulns}
               or bool(set(c["aliases"]) & {a for x in v.features.osv_vulns for a in x.get("aliases", [])}))
    from review_report import package_record
    adv = package_record(c["package"], ver, v).get("advice") or {}
    fix = adv.get("fix_version")
    row["fix_version"] = fix
    if fix:
        try:
            still = osv_ids(c["package"], fix) & ({c["advisory"]} | set(c["aliases"]))
            row["fix_still_vulnerable"] = sorted(still)
        except Exception as e:
            row["fix_check_error"] = repr(e)[:80]
    return row


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0 if sys.argv[1:2] in (["-h"], ["--help"]) else 2
    n, out = int(sys.argv[1]), Path(sys.argv[2])
    cands = candidates()
    rnd = random.Random(SEED)
    todo = []
    for sev, rows in cands.items():
        seen_pkgs, picked = set(), []
        for c in rnd.sample(rows, len(rows)):
            if c["package"].lower() not in seen_pkgs:
                seen_pkgs.add(c["package"].lower())
                picked.append(c)
            if len(picked) >= n:
                break
        todo += picked
    with ThreadPoolExecutor(2) as pool:
        rows = list(pool.map(one, todo))
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=1))
    for sev in ("CRITICAL", "HIGH"):
        rs = [r for r in rows if r["severity"] == sev and "verdict" in r]
        print(sev, len(rs), {k: sum(r["verdict"] == k for r in rs) for k in ("BLOCK", "NEEDS_HUMAN_REVIEW", "ALLOW")},
              "fix proposed", sum(bool(r.get("fix_version")) for r in rs),
              "fix still vulnerable", sum(bool(r.get("fix_still_vulnerable")) for r in rs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
