"""Metrics from results/*.jsonl (run_eval.py): detection at BLOCK and at REVIEW-or-more,
false positives on benign (BLOCK and REVIEW), by source, by sample year, latency p50 / p95. Unreadable files are
counted apart (neither a detection nor a miss).

usage: python3 -I benchmark/report.py [OUT.json] [--aegis aegis-behavior] [--compare aegis] [--suffix eval]
  --aegis FILE      which guard results to report (results/FILE.jsonl, default aegis)
  --compare FILE   also compare with another guard run on the same items (e.g. aegis = before the behavior analysis)
  --suffix S       GuardDog / OSV results of a held-out set (results/guarddog-S.jsonl, osv-S.jsonl)
  Behavior findings (run_eval.py stores them per item): how many samples each finding fired on, with the action the
  policy gave it, and which ones changed a verdict compared with --compare.
GuardDog verdicts: "any threat" = at least one non-capability rule matched; "risk high" = its risk label is high_risk
or critical. OSV: MAL- record for the name + version.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BENCH = Path(os.environ.get("AEGIS_BENCH", str(REPO.parent / "research" / "bench")))
MAL = ("dd-pypi", "malregistry", "dd-npm")
BEN = ("benign-pypi", "benign-npm")


def load(tool: str) -> list[dict]:
    p = BENCH / "results" / f"{tool}.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "-"


def q(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * p))] if xs else 0.0


def aegis_flags(r: dict) -> tuple[bool, bool] | None:
    if r["verdict"] in ("UNREADABLE", "ERROR"):
        return None
    return r["verdict"] == "BLOCK", r["verdict"] in ("BLOCK", "NEEDS_HUMAN_REVIEW")


def gd_flags(r: dict) -> tuple[bool, bool] | None:
    if r.get("threats") is None or (r.get("errors") and not r.get("threats") and r.get("issues") is None):
        return None
    return r.get("risk_label") in ("high_risk", "critical"), bool(r["threats"])


def table(rows: list[dict], flags, key) -> dict:
    out = defaultdict(lambda: {"n": 0, "strict": 0, "any": 0, "unreadable": 0, "secs": []})
    for r in rows:
        k = key(r)
        if k is None:
            continue
        cell = out[k]
        f = flags(r)
        if f is None:
            cell["unreadable"] += 1
            continue
        cell["n"] += 1
        cell["strict"] += f[0]
        cell["any"] += f[1]
        if r.get("seconds") is not None:
            cell["secs"].append(r["seconds"])
    return out


def behavior_section(aegis: list[dict], base: list[dict], result: dict) -> None:
    print("== Behavior check, contribution by finding (samples, by policy action; malicious = detections, benign = false positives)")
    by_key = {(r["dataset"], r["name"], r.get("version")): r for r in base}
    for part, sets in (("mal", MAL), ("benign", BEN)):
        cnt: dict = defaultdict(lambda: defaultdict(int))
        for r in aegis:
            if r["dataset"] not in sets:
                continue
            seen = set()
            for finding, phase, action in r.get("behavior") or []:
                key = (finding, action)
                if key not in seen:
                    seen.add(key)
                    cnt[r["dataset"]][key] += 1
        for ds in sets:
            if ds in cnt:
                items = sorted(cnt[ds].items(), key=lambda x: (-x[1], x[0]))
                print(f"  {ds:12} " + ", ".join(f"{f}/{a}={n}" for (f, a), n in items))
                result.setdefault("behavior_findings", {})[ds] = {f"{f}/{a}": n for (f, a), n in items}
    if not base:
        return
    print("== Compared with the previous run (same samples: before → now, changes at REVIEW or higher)")
    for ds in MAL + BEN:
        pairs = [(by_key.get((r["dataset"], r["name"], r.get("version"))), r) for r in aegis if r["dataset"] == ds]
        pairs = [(o, r) for o, r in pairs if o and aegis_flags(o) is not None and aegis_flags(r) is not None]
        if not pairs:
            continue
        ob = sum(aegis_flags(o)[0] for o, _ in pairs)
        nb = sum(aegis_flags(r)[0] for _, r in pairs)
        oa = sum(aegis_flags(o)[1] for o, _ in pairs)
        na = sum(aegis_flags(r)[1] for _, r in pairs)
        up = sum(1 for o, r in pairs if not aegis_flags(o)[1] and aegis_flags(r)[1])
        down = sum(1 for o, r in pairs if aegis_flags(o)[1] and not aegis_flags(r)[1])
        print(f"  {ds:12} n={len(pairs):5}  BLOCK {pct(ob, len(pairs))} → {pct(nb, len(pairs))}   REVIEW or higher "
              f"{pct(oa, len(pairs))} → {pct(na, len(pairs))}   newly caught {up}, dropped {down}")
        result.setdefault("compare", {})[ds] = {"n": len(pairs), "block_before": ob, "block_after": nb,
                                                "any_before": oa, "any_after": na, "newly_flagged": up, "dropped": down}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="?")
    ap.add_argument("--aegis", default="aegis")
    ap.add_argument("--compare", default="")
    ap.add_argument("--suffix", default="")
    a = ap.parse_args()
    sfx = f"-{a.suffix}" if a.suffix else ""
    aegis, gd, osv = load(a.aegis), load(f"guarddog{sfx}"), load(f"osv{sfx}")
    osv_mal = {(r["dataset"], r["name"], r.get("version")) for r in osv if r.get("mal_ids")}
    result = {}
    print("== Malicious detection (n = analyzed samples, unreadable counted apart)")
    for tool, rows, flags, s_label, a_label in (("AegisPilot", aegis, aegis_flags, "BLOCK", "REVIEW or higher"),
                                                ("GuardDog", gd, gd_flags, "high risk", "1+ threat rules")):
        t = table(rows, flags, lambda r: r["dataset"] if r["dataset"] in MAL else None)
        for ds, c in sorted(t.items()):
            print(f"  {tool:9} {ds:12} n={c['n']:5}  {s_label} {pct(c['strict'], c['n']):>6}  {a_label} {pct(c['any'], c['n']):>6}"
                  f"  unreadable {c['unreadable']}")
            result.setdefault("detection", {}).setdefault(tool, {})[ds] = {k: v for k, v in c.items() if k != "secs"}
    # OSV baseline and AegisPilot + OSV
    for ds in MAL:
        its = [r for r in aegis if r["dataset"] == ds and aegis_flags(r) is not None]
        if not its:
            continue
        hit = [r for r in its if (r["dataset"], r["name"], r.get("version")) in osv_mal]
        both = [r for r in its if (r["dataset"], r["name"], r.get("version")) in osv_mal or aegis_flags(r)[1]]
        print(f"  OSV(MAL)  {ds:12} n={len(its):5}  known malicious {pct(len(hit), len(its)):>6}   AegisPilot+OSV REVIEW or higher {pct(len(both), len(its))}")
        result.setdefault("detection", {}).setdefault("OSV", {})[ds] = {"n": len(its), "mal": len(hit), "aegis_or_osv": len(both)}
    print("== Benign false positives (n = analyzed samples)")
    for tool, rows, flags, s_label, a_label in (("AegisPilot", aegis, aegis_flags, "BLOCK", "REVIEW or higher"),
                                                ("GuardDog", gd, gd_flags, "high risk", "1+ threat rules")):
        t = table(rows, flags, lambda r: f"{r['dataset']}/{r['group']}" if r["dataset"] in BEN else None)
        for k, c in sorted(t.items()):
            print(f"  {tool:9} {k:22} n={c['n']:5}  {s_label} {pct(c['strict'], c['n']):>6}  {a_label} {pct(c['any'], c['n']):>6}"
                  f"  unreadable {c['unreadable']}")
            result.setdefault("false_positive", {}).setdefault(tool, {})[k] = {k2: v for k2, v in c.items() if k2 != "secs"}
    print("== Malicious detection by sample year (Datadog: date in the file name)")
    for tool, rows, flags in (("AegisPilot", aegis, aegis_flags), ("GuardDog", gd, gd_flags)):
        t = table(rows, flags, lambda r: f"{r['dataset']}/{(r.get('date') or '')[:4]}" if r["dataset"] in ("dd-pypi", "dd-npm") and r.get("date") else None)
        for k, c in sorted(t.items()):
            print(f"  {tool:9} {k:16} n={c['n']:5}  strict {pct(c['strict'], c['n']):>6}  broad {pct(c['any'], c['n']):>6}")
            result.setdefault("by_year", {}).setdefault(tool, {})[k] = {k2: v for k2, v in c.items() if k2 != "secs"}
    print("== Scan time (seconds, files already local: download excluded)")
    for tool, rows in (("AegisPilot", aegis), ("GuardDog", gd)):
        for grp in ("mal", "benign"):
            s = [r["seconds"] for r in rows if (r["dataset"] in MAL) == (grp == "mal") and r.get("seconds") is not None]
            if s:
                print(f"  {tool:9} {grp:6} n={len(s):5} p50 {statistics.median(s):.2f}  p95 {q(s, 0.95):.2f}  max {max(s):.1f}")
                result.setdefault("seconds", {}).setdefault(tool, {})[grp] = {"n": len(s), "p50": statistics.median(s), "p95": q(s, 0.95), "max": max(s)}
    behavior_section(aegis, load(a.compare) if a.compare else [], result)
    if a.out:
        Path(a.out).write_text(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
