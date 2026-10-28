"""
AegisPilot - what every per-source check shares.

A check (checks/<source>.py) takes the parsed install (install_parse.Parsed) and returns its records: one dict per
package / file / script it looked at (review_report.package_record shape) with the verdict after the post rules and the
allow / deny lists. guard_core.check_parsed runs the checks of the registry (checks/__init__.py) side by side and only
decides on what they return; adding a source = a module here and a line in the registry.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from review_report import clean, package_record, unscanned_record

POST_LABELS = {"new_package": "newly registered package", "typosquat": "possible typosquatting", "osv_unavailable": "vulnerability DB lookup failed",
               "new_risky_code": "risky code new in this version", "late_file": "file recently added to an old version"}


@dataclass
class Outcome:
    """What one check found: [(record, verdict)] in a stable order, and report fields of its own ({"transitive": ...}).
    dependencies: records about what the named things pull in - they come after every check's own records, so the
    card leads with what the command names."""
    records: list = field(default_factory=list)
    dependencies: list = field(default_factory=list)
    report: dict = field(default_factory=dict)

    def add(self, rec: dict, verdict: str, dependency: bool = False) -> None:
        (self.dependencies if dependency else self.records).append((rec, verdict))

    def timed_out(self, name: str, version, ecosystem: str = "pypi") -> None:
        """A package the check did not finish within the command's budget: the same REVIEW as a scan that timed out
        (review_report.failure_kind "timeout": try once more, else tell the user)."""
        import scan_engine
        f = scan_engine.ScanFeatures(name=name, version=version, ecosystem=ecosystem,
                                     fetch_error="scan timed out (this command's scan time budget is used up)")
        self.add(package_record(name, version, scan_engine.Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {f.fetch_error}"], f)),
                 "NEEDS_HUMAN_REVIEW")

    def unscanned(self, kind: str, text: str, reason: str) -> None:
        """A source the check could not read: a REVIEW that says so, never a silent pass."""
        self.add(unscanned_record({"kind": kind, "text": text, "reason": reason}), "NEEDS_HUMAN_REVIEW")


@dataclass
class Check:
    """name: the source it covers; wants(parsed): anything for it in this command; run(ctx) -> Outcome;
    on_timeout(ctx) -> Outcome: what is recorded when it did not finish within the command's budget."""
    name: str
    wants: Callable
    run: Callable
    on_timeout: Callable


class Context:
    """What the checks of one install decision share: the parsed command, the project, the allow / deny lists, the
    scanner (guard_core.scan_packages - replaceable in tests), the budget, and one OSV reachability probe."""

    def __init__(self, parsed, project_dir: str, scan_packages, deadline: float):
        self.parsed, self.project_dir, self.scan_packages, self.deadline = parsed, project_dir, scan_packages, deadline
        try:
            from policy import decide, load
            self.pol, self.policy_decide = load(project_dir), decide
        except Exception:
            self.pol, self.policy_decide = None, None     # the policy stage is an addition; the scan verdict stands without it
        self._osv: dict = {}
        self._osv_done = threading.Event()
        self._osv_lock = threading.Lock()
        self._osv_started = False

    def start_osv(self) -> None:
        """Probe OSV once, beside the scans (post_rules.osv_reachable). Started only by checks that use OSV: a probe
        nobody waits for can still be inside SSL code when the interpreter exits, which crashed test runs."""
        with self._osv_lock:
            if self._osv_started:
                return
            self._osv_started = True

        def probe():
            try:
                from post_rules import osv_reachable
                self._osv["ok"] = osv_reachable()
            except Exception:
                self._osv["ok"] = False
            finally:
                self._osv_done.set()
        threading.Thread(target=probe, daemon=True).start()

    def osv_ok(self) -> bool:
        """Did OSV answer? The scans read an OSV error as "no vulnerability", so the post rules need to know."""
        self.start_osv()
        try:
            from post_rules import OSV_PROBE_TIMEOUT
        except Exception:
            OSV_PROBE_TIMEOUT = 10
        self._osv_done.wait(OSV_PROBE_TIMEOUT)
        return self._osv.get("ok", False)               # still running or failed: OSV did not answer in time

    def left(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def policy(self, rec: dict, name: str, version, verdict: str) -> str:
        return policy_into(rec, self.pol, self.policy_decide, name, version, verdict)


def post_rules_into(rec: dict, result, version, osv_ok: bool, vdiff, late) -> None:
    """The rules applied after the scan (post_rules.py, only ever ALLOW -> REVIEW) and their evidence in the record."""
    try:                                       # rules applied after the scan (post_rules.py): only ever ALLOW -> REVIEW
        from post_rules import apply as post_apply
        new_verdict, fired = post_apply(result, version, osv_ok, vdiff, late)
    except Exception:
        new_verdict, fired = result.verdict, None
    if fired:
        result.verdict = new_verdict
        rec["verdict"] = new_verdict
        if fired["rule"] == "known_malicious":
            rec["evidence"] = [{"rule": "known_malicious", "label": "known malicious version", "location": ", ".join(fired["ids"]),
                                "snippet": "", "count": len(fired["ids"])}] + [e for e in rec["evidence"] if e.get("rule") != "score"]
            rec["headline"] = "known malicious version"
            rec["malicious_ids"] = fired["ids"]
        if fired["rule"] == "typosquat":
            rec["headline"] = "possible typosquatting"
            rec.setdefault("advice", {})["typosquat_of"] = fired["of"]
            if not any(e.get("rule") == "typosquat" for e in rec["evidence"]):
                rec["evidence"] = [{"rule": "typosquat", "label": "possible typosquatting", "location": f"name similar to '{fired['of']}'",
                                    "snippet": "", "count": 1}] + rec["evidence"]
        if fired["rule"] == "new_risky_code":
            first = fired["signals"][0]
            where = f"{first['file']} ({first['detail']})"
            since = fired.get("since")
            rec["evidence"] = [{"rule": "new_risky_code", "label": "risky code new in this version",
                                "location": clean(where, 120),
                                "snippet": clean(f"not in the previous version {fired['previous']}" if not since else
                                                 f"present since {since['version']} ({since['days']} days ago)", 80),
                                "count": len(fired["signals"])}] + [e for e in rec["evidence"] if e.get("rule") != "score"]
            rec["headline"] = "risky code new in this version"
            if fired.get("safe_version"):
                rec.setdefault("advice", {})["pin_version"] = clean(str(fired["safe_version"]), 40)
            rec["new_risky_code"] = {"previous": fired["previous"], "since": since, "safe_version": fired.get("safe_version"),
                                     "signals": [{k: clean(str(h[k]), 120) for k in ("kind", "file", "detail")} for h in fired["signals"][:5]]}
        if fired["rule"] == "late_file":
            rec["evidence"] = [{"rule": "late_file", "label": "file recently added to an old version",
                                "location": clean(fired["file"], 120),
                                "snippet": clean(f"added to the version released {fired['release_date']}, {fired['added_days_after']} days later ({fired['added_days_ago']} days ago)", 80),
                                "count": 1}] + [e for e in rec["evidence"] if e.get("rule") != "score"]
            rec["headline"] = "file recently added to an old version"
            rec["late_file"] = {k: fired.get(k) for k in ("file", "release_date", "added_days_after", "added_days_ago")}
            if fired.get("safe_version"):
                rec.setdefault("advice", {})["pin_version"] = clean(str(fired["safe_version"]), 40)
        if fired["rule"] == "osv_unavailable":
            rec["evidence"] = [{"rule": "osv_unavailable", "label": "vulnerability DB lookup failed", "location": "OSV",
                                "snippet": "", "count": 1}] + [e for e in rec["evidence"] if e.get("rule") != "score"]
            rec["headline"] = "vulnerability DB lookup failed"
        if fired["rule"] == "new_package":
            rec["evidence"] = [{"rule": "new_package", "label": "newly registered package", "location": f"first published on PyPI {fired['days']} days ago",
                                "snippet": "", "count": 1}] + [e for e in rec["evidence"] if e.get("rule") != "score"]
            rec["headline"] = "newly registered package"
            rec["new_package_days"] = fired["days"]


def policy_into(rec: dict, pol, policy_decide, name: str, version, verdict: str) -> str:
    """The allow / deny lists (policy.py) applied to one package record; returns the verdict after them."""
    if pol is not None:
        try:
            verdict, note = policy_decide(pol, name, rec.get("version") or version, verdict)
        except Exception:
            note = None
        if note:
            rec["policy"] = note
            if note["action"] == "deny":
                rec["verdict"] = "BLOCK"
                rec["evidence"] = [{"rule": "policy_deny", "label": "package denied by policy", "location": f"{note['source']} policy",
                                    "snippet": note["reason"], "count": 1}] + rec["evidence"]
                rec["headline"] = "package denied by policy"
            elif note["action"] == "allow":
                rec["verdict"] = "ALLOW"
    return verdict


def internal_package(rec: dict, result, parsed) -> bool:
    """A package that is not on the public registry while the person's own index is in use: a company package (installed
    from that index, which the person chose). Recorded, not flagged."""
    if not getattr(parsed, "trusted_indexes", None) or getattr(result.features, "fetch_ok", True):
        return False
    from review_report import failure_kind
    if failure_kind(result.features.fetch_error) != "not_found":
        return False
    rec["internal_index"] = {"indexes": [clean(u, 120) for u in parsed.trusted_indexes[:3]],
                             "note": "name not in the public registry: treated as a package from an in-house index a person set up (code not scanned)"}
    rec["verdict"] = "ALLOW"
    return True
