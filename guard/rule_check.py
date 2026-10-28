"""
Rule examples and the rule list.

Every rule in guard/rules/ has examples in guard/rules/examples/: inputs it must catch ("hit") and inputs it must let
through ("miss"). This runs them against the rule files and fails when an example is not met, when a rule has no hit or
no miss example, or when an example names a rule that no longer exists. It also writes guard/rules/RULES.md, the list
of every rule, from the rule files themselves (so the list cannot drift from what the guard does).

usage: python3 rule_check.py [--rules DIR]          run every example (exit 1 on any failure)
       python3 rule_check.py --doc [--check]        write RULES.md (--check: exit 1 if it is stale instead)
       python3 rule_check.py --modules              the rule modules on top (~/.aasm/rules, /etc/aasm/rules): which apply,
                                                    why one is skipped, and each module's own "examples"
The first two read the base rules only (rule modules off); --modules reads the rules as the guard uses them.

Example files (one per kind of rule; each maps a rule id to a list of cases):
  static.json        rules.json      {"expect": "hit"|"miss", "why", "files": {path: text},
                                      "layout": "wheel"|"sdist"|"npm"|"bundle", "ecosystem": "pypi"|"npm"|"bundle",
                                      "evidence": the evidence id to look for (default: the rule's evidence id)}
  hard.json          scoring.json    {"expect", "why", "features": {ScanFeatures field: value}, "mode": "rules"|"ml",
                                      "verdict": expected score_rules verdict (optional)}
  post.json          post.json       {"expect", "why", "scan_verdict", "features", "osv_ok", "vdiff", "late",
                                      "verdict": expected verdict after the rules (optional)}
  version_diff.json  post.json       {"expect", "why", "new": {path: text}, "old": {path: text} | null}
Nothing is downloaded or run: static examples are written to a temporary folder and read like an unpacked package.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

GUARD = Path(__file__).resolve().parent
KINDS = ("static", "hard", "post", "version_diff")
VD_KINDS = ("import_time", "binary_py", "new_pth", "encoded_payload")
VERDICT_LABEL = {"ALLOW": "allow", "NEEDS_HUMAN_REVIEW": "review", "BLOCK": "block"}
# evidence ids made by code rather than by a rule file (review_report / guard_core)
CODE_EVIDENCE = ("osv", "typosquat", "reputation", "score", "fetch_error", "unscanned_source", "policy_deny")


def evidence_ids(rs) -> set[str]:
    """Every evidence id a guard record can carry: rules.json ids and their evidence_ids, post.json rules, code-made ones."""
    import rule_engine
    out = {rule_engine.evidence_id(r) for r in rs.rules if not r.get("evidence_ids")}   # evidence_ids: leaves those instead
    out |= {v for r in rs.rules for v in r.get("evidence_ids", {}).values()}
    return out | {r["id"] for r in rs.post_rules} | set(CODE_EVIDENCE)


def check_capabilities(rs, rules_dir: Path) -> list[str]:
    """capabilities.json must say what every evidence id means for an attack path (null counts) and name nothing else:
    a rule added without it is silently missing from every path (this once left the exfiltration, prompt-injection
    and bundled-binary rules with 0 paths)."""
    import attack_path
    try:
        caps = attack_path.load_capabilities(rules_dir / "capabilities.json")
    except attack_path.CapabilitiesError as e:
        return [f"capabilities.json: {e}"]
    ids = evidence_ids(rs)
    problems = [f"capabilities.json: evidence '{i}' has no meaning for attack paths (a capability id or null)" for i in sorted(ids - set(caps["findings"]))]
    import package_caps
    kinds = set(package_caps._analyzer().KINDS) | {"dynamic_code"}       # what package_caps.extract can report
    problems += [f"capabilities.json: package capability '{k}' is missing from package_capabilities" for k in sorted(kinds - set(caps["package_capabilities"]))]
    problems += [f"capabilities.json: evidence '{i}' is not left by any rule" for i in sorted(set(caps["findings"]) - ids)]
    return problems


def rule_ids(rs) -> dict[str, list[str]]:
    return {"static": [r["id"] for r in rs.rules], "hard": [h["id"] for h in rs.hard_rules],
            "post": [r["id"] for r in rs.post_rules], "version_diff": list(VD_KINDS)}


def load_examples(rules_dir: Path) -> dict[str, dict]:
    out = {}
    for kind in KINDS:
        f = rules_dir / "examples" / f"{kind}.json"
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except FileNotFoundError:
            data = {"examples": {}}
        out[kind] = data.get("examples", {})
    return out


def _features(se, name: str, values: dict, **base):
    f = se.ScanFeatures(name=name, version="1.0", **base)
    for k, v in (values or {}).items():
        if not hasattr(f, k):
            raise ValueError(f"unknown feature '{k}'")
        if k == "skipped_members":
            v = [tuple(x) for x in v]
        setattr(f, k, v)
    return f


def _package(tmp: Path, case: dict) -> list[Path]:
    name = case.get("name", "examplepkg")
    layout = case.get("layout", "wheel")
    if layout == "sdist":
        root = tmp / f"{name}-1.0.tar.gz.unpacked" / f"{name}-1.0"
    elif layout == "npm":                       # an npm tarball unpacks into package/
        root = tmp / f"{name}-1.0.tgz.unpacked" / "package"
    elif layout == "bundle":                    # a skill / plugin folder
        root = tmp / f"{name}.bundle.unpacked" / name
    else:
        root = tmp / f"{name}-1.0-py3-none-any.whl.unpacked"
    for rel, text in case["files"].items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    files = sorted(tmp.rglob("*"))
    if layout == "npm":                         # lifecycle scripts as package.json#<event>.sh, like sources/npm.fetch
        from sources import npm
        files += npm.write_lifecycle(files, tmp, name)
    return files


def run_case(kind: str, rule_id: str, case: dict, rs, mods) -> tuple[bool, str, str | None]:
    """(did the rule fire, a short note on what happened, the final verdict when the case names one to expect)."""
    se, rule_engine, post_rules, version_diff = mods
    if kind == "static":
        with tempfile.TemporaryDirectory() as t:
            files = _package(Path(t), case)
            f = se.ScanFeatures(name=case.get("name", "examplepkg"), version="1.0", ecosystem=case.get("ecosystem", "pypi"))
            rule_engine.run_static(rs, files, f)
        rule = next(r for r in rs.rules if r["id"] == rule_id)
        want = case.get("evidence", rule_engine.evidence_id(rule))
        found = sorted({e["rule"] for e in f.evidence})
        return want in found, f"evidence: {', '.join(found) or 'none'}", None
    if kind == "hard":
        f = _features(se, case.get("name", "examplepkg"), case.get("features"))
        h = next(x for x in rs.hard_rules if x["id"] == rule_id)
        mode = case.get("mode", "rules")
        fired = mode in h.get("modes", ["rules", "ml"]) and rule_engine._cond(h["when"], f)
        verdict, score, _ = rule_engine.score_rules(rs, f)
        return fired, f"verdict {verdict} {score}", verdict
    if kind == "post":
        f = _features(se, case.get("name", "examplepkg"), case.get("features"), fetch_ok=True)
        res = se.Verdict(case.get("scan_verdict", "ALLOW"), 0.1, [], f)
        verdict, fired = post_rules.apply(res, None, case.get("osv_ok", True), case.get("vdiff"), case.get("late"))
        hit = bool(fired) and fired["rule"] == rule_id
        return hit, f"verdict {verdict}, matched rule {fired['rule'] if fired else 'none'}", verdict
    if kind == "version_diff":
        new = {k: v.splitlines() for k, v in case["new"].items()}
        old = {k: v.splitlines() for k, v in case["old"].items()} if case.get("old") is not None else None
        kinds = sorted({h["kind"] for h in version_diff.signals(new, old)})
        return rule_id in kinds, f"signals: {', '.join(kinds) or 'none'}", None
    raise ValueError(kind)


def check(rules_dir: Path) -> list[str]:
    """Problems found ([] = every example met and every rule covered)."""
    import post_rules
    import rule_engine
    import scan_engine as se
    import version_diff
    rs = rule_engine.current()
    mods = (se, rule_engine, post_rules, version_diff)
    examples = load_examples(rules_dir)
    ids = rule_ids(rs)
    problems = check_capabilities(rs, rules_dir)
    for kind in KINDS:
        for rule_id in ids[kind]:
            cases = examples[kind].get(rule_id, [])
            for want in ("hit", "miss"):
                if not any(c.get("expect") == want for c in cases):
                    problems.append(f"{kind}/{rule_id}: no '{want}' example")
        for rule_id, cases in examples[kind].items():
            if rule_id not in ids[kind]:
                problems.append(f"{kind}/{rule_id}: example for a rule that is not in the rule files")
                continue
            for i, case in enumerate(cases, 1):
                if case.get("expect") not in ("hit", "miss"):
                    problems.append(f"{kind}/{rule_id} #{i}: expect must be hit or miss")
                    continue
                try:
                    fired, note, verdict = run_case(kind, rule_id, case, rs, mods)
                except Exception as e:
                    problems.append(f"{kind}/{rule_id} #{i}: could not run the example: {type(e).__name__}: {e}")
                    continue
                if fired != (case["expect"] == "hit"):
                    what = "should match but passed" if case["expect"] == "hit" else "should pass but matched"
                    problems.append(f"{kind}/{rule_id} #{i} ({case.get('why', '')}): {what} - {note}")
                elif "verdict" in case and verdict != case["verdict"]:
                    problems.append(f"{kind}/{rule_id} #{i} ({case.get('why', '')}): verdict should be {case['verdict']} but is "
                                    f"{verdict} - {note}")
    return problems


def check_modules() -> tuple[list[str], list[str]]:
    """The rule modules on top of the base rules (rule_modules.py): (report lines, problems). A skipped module is a
    problem; so is an example of an applied module that is not met (run on the rules with every module applied)."""
    import post_rules
    import rule_engine
    import scan_engine as se
    import version_diff
    rs = rule_engine.current()
    mods = (se, rule_engine, post_rules, version_diff)
    ids = rule_ids(rs)
    lines, problems = [], []
    for m in rs.modules:
        name = f"{m.get('name', '')} ({m['file']})"
        if m["status"] != "applied":
            problems.append(f"{name}: skipped - {m.get('error')}")
            continue
        lines.append(f"applied: {name} {m.get('changes')}")
        for kind, by_id in (m.get("examples") or {}).items():
            if kind not in KINDS:
                problems.append(f"{name}: unknown example kind '{kind}'")
                continue
            for rule_id, cases in by_id.items():
                if rule_id not in ids[kind]:
                    problems.append(f"{name}: {kind}/{rule_id}: example for a rule that is not in the applied rules")
                    continue
                for i, case in enumerate(cases, 1):
                    try:
                        fired, note, verdict = run_case(kind, rule_id, case, rs, mods)
                    except Exception as e:
                        problems.append(f"{name}: {kind}/{rule_id} #{i}: could not run the example: {type(e).__name__}: {e}")
                        continue
                    if fired != (case.get("expect") == "hit"):
                        what = "should match but passed" if case.get("expect") == "hit" else "should pass but matched"
                        problems.append(f"{name}: {kind}/{rule_id} #{i} ({case.get('why', '')}): {what} - {note}")
                    elif "verdict" in case and verdict != case["verdict"]:
                        problems.append(f"{name}: {kind}/{rule_id} #{i}: verdict should be {case['verdict']} but is {verdict}")
    return lines, problems


# ------------------------------------------------------------------------------------------------ RULES.md

def _cond_text(c: dict) -> str:
    if "all" in c:
        return " and ".join(_cond_text(x) for x in c["all"])
    if "any" in c:
        return "(" + " or ".join(_cond_text(x) for x in c["any"]) + ")"
    if "evidence" in c:
        return f"evidence `{c['evidence']}`"
    return f"`{c['field']}` = {json.dumps(c['equals'], ensure_ascii=False)}" if "equals" in c else f"`{c['field']}`"


def _values(rule: dict, skip=("id", "title", "detector", "references", "examples")) -> str:
    parts = []
    for k, v in rule.items():
        if k in skip:
            continue
        parts.append(f"{k}={json.dumps(v, ensure_ascii=False)}")
    return "<br>".join(f"`{p}`" for p in parts)


def _count(examples: dict, kind: str, rule_id: str) -> str:
    cases = examples[kind].get(rule_id, [])
    return f"{sum(c.get('expect') == 'hit' for c in cases)} / {sum(c.get('expect') == 'miss' for c in cases)}"


def _cell(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_doc(rules_dir: Path) -> str:
    import rule_engine
    rs = rule_engine.load(rules_dir)
    ex = load_examples(rules_dir)
    sig = rs.raw["signals"]["signals"]
    post = rs.raw["post"]
    out = ["# Rule list", "",
           "> Generated file. Do not edit it by hand: change the rule files, then rebuild it with `python3 guard/rule_check.py --doc`.",
           "> The examples column counts the hit / miss examples in `guard/rules/examples/`.", ""]

    out += ["## 1. Package file checks (`rules.json`)", "",
            "Applied top to bottom; this is the order evidence piles up in.", "",
            "| # | id | what | detector | values | examples |", "|---|---|---|---|---|---|"]
    for i, r in enumerate(rs.rules, 1):
        out.append(f"| {i} | `{r['id']}` | {_cell(r.get('title', ''))} | `{r['detector']}` | {_cell(_values(r))} | "
                   f"{_count(ex, 'static', r['id'])} |")

    th = rs.raw["scoring"]["thresholds"]
    out += ["", "## 2. Score and verdict (`scoring.json`)", "",
            f"A score of {th['block']} or more blocks; {th['review']} or more asks for review.", "",
            "| subscore | weight |", "|---|---|"]
    out += [f"| `{k}` | {v} |" for k, v in rs.raw["scoring"]["weights"].items()]
    out += ["", f"With an ML result: ML score weight {rs.ml_weight}, subscores used with it: "
            + ", ".join(f"`{s}`" for s in rs.ml_subscores) + ".", "",
            "### Hard rules", "", "Checked top to bottom; the first block that matches ends the verdict. A review rule raises the score above the review threshold.", "",
            "| # | id | action | condition | modes | reason text | examples |", "|---|---|---|---|---|---|---|"]
    for i, h in enumerate(rs.hard_rules, 1):
        act = "block" if h["action"] == "block" else "review"
        modes = ", ".join(h.get("modes", ["rules", "ml"]))
        out.append(f"| {i} | `{h['id']}` | {act} | {_cell(_cond_text(h['when']))} | {modes} | {_cell(h['reason'])} | "
                   f"{_count(ex, 'hard', h['id'])} |")

    out += ["", "## 3. Verdict adjustments after the scan (`post.json`)", "",
            "Checked top to bottom; only the first rule that matches and whose 'applies to' includes the scan verdict is applied.", "",
            "| # | id | what | applies to | result | examples |", "|---|---|---|---|---|---|"]
    for i, r in enumerate(rs.post_rules, 1):
        to = "all" if r["applies_to"] == "any" else ", ".join(VERDICT_LABEL[v] for v in r["applies_to"])
        out.append(f"| {i} | `{r['id']}` | {_cell(r.get('title', ''))} | {to} | {VERDICT_LABEL[r['verdict']]} | "
                   f"{_count(ex, 'post', r['id'])} |")

    titles = post["version_diff"].get("signal_titles", {})
    out += ["", "### Signals checked against the previous release (`post.json` → `version_diff`)", "",
            "| signal | what | examples |", "|---|---|---|"]
    for k in VD_KINDS:
        out.append(f"| `{k}` | {_cell(titles.get(k, ''))} | {_count(ex, 'version_diff', k)} |")

    import attack_path
    caps = attack_path.load_capabilities(rules_dir / "capabilities.json")
    out += ["", "## 4. Attack paths (`capabilities.json`)", "",
            "Path = package capability (what the code does) → who runs it → our capabilities and assets. Paths explain; they do not affect the verdict.", "",
            "### Package capabilities (reported by code analysis)", "", "| capability | description | how it reaches us |", "|---|---|---|"]
    for k, v in caps["package_capabilities"].items():
        how = ", ".join(v.get("reach", [])) or ("channel (sends what was read out)" if v.get("channel") else "none")
        out.append(f"| `{k}` | {_cell(v['text'])} | {how} |")
    out += ["", "Phases: " + ", ".join(f"`{k}` = {v['text']}" for k, v in caps["phases"].items()) + ".", "",
            "### Fallback when the code cannot be seen (evidence → capability)", "",
            "Used for removed malicious releases, source that was not scanned, and evidence that is not code (instructions aimed at the agent). none = not linked into a path.", "",
            "| evidence | capability | context | confidence |", "|---|---|---|---|"]
    for fid in sorted(caps["findings"]):
        cid = caps["findings"][fid]
        if cid is None:
            out.append(f"| `{fid}` | none | | |")
        else:
            c = caps["capabilities"][cid]
            conf = "confirmed" if c.get("confidence", "confirmed") == "confirmed" else "possible"
            out.append(f"| `{fid}` | {_cell(c['text'])} | {_cell(caps['contexts'][c['context']])} | {conf} |")

    out += ["", "## 5. Signal dictionary (`signals.json`)", "", "| signal | description | patterns |", "|---|---|---|"]
    for name, s in sig.items():
        n = len(s.get("literals", [])) + len(s.get("regex", []))
        out.append(f"| `{name}` | {_cell(s.get('description', ''))} | {n} |")
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the rule examples and build the rule list (RULES.md)")
    ap.add_argument("--rules", help="rules folder (default: guard/rules or AASM_RULES_DIR)")
    ap.add_argument("--doc", action="store_true", help="write RULES.md")
    ap.add_argument("--check", action="store_true", help="with --doc: only check that it is up to date, do not write")
    ap.add_argument("--modules", action="store_true",
                    help="check the rule modules on top of the base rules (~/.aasm/rules, /etc/aasm/rules) and run their examples")
    args = ap.parse_args(argv)
    if args.rules:
        os.environ["AASM_RULES_DIR"] = str(Path(args.rules).resolve())
    if not args.modules:                                 # the base rules and their examples / RULES.md: no modules
        os.environ["AASM_RULE_MODULES"] = "0"
    sys.path.insert(0, str(GUARD))
    import rule_engine
    if args.modules:
        try:
            lines, problems = check_modules()
        except rule_engine.RulesetError as e:
            print(f"rule file error: {e}")
            return 1
        for line in lines:
            print(line)
        if not lines and not problems:
            print("no rule modules (~/.aasm/rules/*.json, admin /etc/aasm/rules/*.json)")
        for p in problems:
            print(f"  - {p}")
        return 1 if problems else 0
    rules_dir = Path(rule_engine.RULES_DIR)
    if args.doc:
        text = render_doc(rules_dir)
        target = rules_dir / "RULES.md"
        if args.check:
            current = target.read_text(encoding="utf-8") if target.exists() else ""
            if current != text:
                print(f"{target} does not match the rule files. Rebuild it with python3 guard/rule_check.py --doc.")
                return 1
            print("RULES.md is up to date")
            return 0
        target.write_text(text, encoding="utf-8")
        print(f"wrote {target}")
        return 0
    try:
        problems = check(rules_dir)
    except rule_engine.RulesetError as e:
        print(f"rule file error: {e}")
        return 1
    if problems:
        print(f"{len(problems)} example problems:")
        for p in problems:
            print(f"  - {p}")
        return 1
    ex = load_examples(rules_dir)
    print(f"rule examples passed: {sum(len(c) for k in KINDS for c in ex[k].values())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
