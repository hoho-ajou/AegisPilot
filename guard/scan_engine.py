"""
AegisPilot - core scan engine

Implements pipeline stages 2~4 (+ rule-based stage 6):
  2. Fetch  - download wheel/sdist WITHOUT running install scripts
  3. Static analysis - entropy, dangerous keywords, install hooks, typosquat distance
  4. Vulnerability lookup - OSV.dev
  6. Verdict - weighted rule-based scoring -> ALLOW / NEEDS_HUMAN_REVIEW / BLOCK

Stage 5 (dynamic sandbox observation) and stage 7 (rollback) are NOT implemented.
"""
from __future__ import annotations

import net
import io
import json
import os
import re
import tarfile
import tempfile
import threading
import urllib.request
import warnings
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import safe_extract

from sources import pypi  # noqa: E402  (PyPI's project JSON and release files: sources/pypi.py)
MAX_DOWNLOAD_BYTES = pypi.MAX_DOWNLOAD_BYTES          # also the local-file ceiling (scan_local_file)
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

# --- rules -------------------------------------------------------------------
# Every detection value (patterns, windows, weights, thresholds, hard rules and their reasons) lives in the rule
# files under guard/rules/ and is applied by rule_engine.py. The names below are kept so existing callers and
# experiments keep working; they are read from the loaded ruleset, not defined here.
import rule_engine  # noqa: E402
# package code is parsed, never run: its own SyntaxWarnings ("invalid escape sequence") are not ours to print
warnings.filterwarnings("ignore", category=SyntaxWarning)

RULESET = rule_engine.current()

POPULAR_PACKAGES = RULESET.sub["typosquat"]["popular_names"]
DANGEROUS_KEYWORDS = RULESET.keyword_literals["dangerous_keywords"]
_KEYWORD_PATTERNS = dict(zip(DANGEROUS_KEYWORDS, RULESET.sig("dangerous_keywords")))
INSTALL_HOOK_PATTERNS = RULESET.sig("install_hook")
CHAIN_LINE_WINDOW = RULESET.window_of("decode_then_exec")
_DECODE_PATTERNS = RULESET.sig("decode")
_EXEC_PATTERNS = RULESET.sig("exec")
_DOWNLOAD_PATTERNS = RULESET.sig("download")
_EXECUTE_PATTERNS = RULESET.sig("execute")
_TEST_PATH_PATTERN = RULESET.test_path
_DEV_TOPLEVEL = RULESET.dev_toplevel
MAX_EVIDENCE_PER_RULE = RULESET.max_evidence
SNIPPET_MAX = RULESET.snippet_max
MAX_LITERAL_SCAN_BYTES = RULESET.max_literal_scan_bytes


def _string_spans(text: str) -> list[tuple[int, int]]:
    return rule_engine.string_spans(RULESET, text)


def _is_test_path(path: Path) -> bool:
    return rule_engine.is_test_path(RULESET, path)


def _is_dev_path(path: Path) -> bool:
    return rule_engine.is_dev_path(RULESET, path)


def _find_chain(lines: list[str], group_a: list[re.Pattern], group_b: list[re.Pattern],
                window: int, text: str | None = None) -> tuple[int, int] | None:
    return rule_engine.find_chain(RULESET, lines, group_a, group_b, window, text)


def _resolve_aliases(text: str) -> str:
    return rule_engine.resolve_aliases(RULESET, text)


def _install_time_setups(files: list[Path]) -> set[Path]:
    return rule_engine.install_time_setups(RULESET, files)


_package_relative = rule_engine.package_relative
_archive_depth = rule_engine.archive_depth
_levenshtein = rule_engine.levenshtein
_shannon_entropy = rule_engine.shannon_entropy


def _add_evidence(features: "ScanFeatures", rule: str, path: Path, lines: list[str], idx: int,
                  extra: dict | None = None) -> None:
    rule_engine.add_evidence(RULESET, features, rule, path, lines, idx, extra)



@dataclass
class ScanFeatures:
    name: str
    version: str | None
    ecosystem: str = "pypi"            # signals.json "ecosystems": which languages are read as code (pypi / npm / bundle)
    resolved_version: str | None = None
    fetch_ok: bool = False
    fetch_error: str | None = None

    max_entropy: float = 0.0
    keyword_hits: dict = field(default_factory=dict)
    keyword_total: int = 0
    has_install_hook: bool = False
    has_decode_then_exec: bool = False
    has_download_then_execute: bool = False
    file_count: int = 0
    py_file_count: int = 0
    py_loc: int = 0                    # non-test .py lines (keyword normalization)

    setup_keyword_total: int = 0       # dangerous keywords inside setup.py only
    setup_import_keyword_total: int = 0   # ...and in the local modules setup.py imports (its install hook can run them)
    setup_network: bool = False        # network call at install time
    setup_hidden_shell: bool = False   # powershell/EncodedCommand/pythonw at install time

    pth_exec: bool = False             # .pth line / root sitecustomize.py runs risky code at every interpreter start
    behavior_block: bool = False       # the behavior analysis (guard/behavior) found a fact rules/behavior.json blocks
    behavior_review: bool = False      # ...one it sends to review
    behavior_not_analyzed: list = field(default_factory=list)   # [(file, why)] files the behavior analysis skipped
    pth_chain: bool = False            # ...and it is a decode->exec or download->execute chain
    artifact: str | None = None        # file name that was analyzed
    artifact_kind: str | None = None   # "wheel" | "sdist"
    install_time_files: list = field(default_factory=list)   # npm: files the install scripts run (sources/npm.install_time_files)
    skipped_members: list = field(default_factory=list)   # [(name, reason)] members with unsafe names the extractor skipped
    dependencies: list = field(default_factory=list)   # direct deps that apply to a plain install [{name, spec, extras}]
    requires_dist: list = field(default_factory=list)  # the release's raw Requires-Dist (extras asked for are applied later)
    deps_error: str | None = None

    min_edit_distance: int | None = None
    closest_popular_name: str | None = None

    osv_vulns: list = field(default_factory=list)
    analysis_skipped: str | None = None          # why the code was not analyzed (OSV already lists the release as malicious)
    command_stopped: bool = False                # not finished: another package of the same command is a BLOCK
    from_cache: bool = False                     # an ALLOW reused for the same file within 6 hours (verdict_cache.py)
    osv_max_severity: str | None = None

    maintainer_count: int | None = None
    package_age_days: float | None = None
    release_age_hours: float | None = None   # hours since the version being installed was first uploaded (None: unknown)
    settled_version: str | None = None       # when that is under the fresh-release limit: the newest earlier version past it
    has_readme: bool = False

    # [{rule, file, line, snippet, ...}] - rules: decode_then_exec,
    # download_then_execute, install_hook, high_entropy, keyword
    evidence: list = field(default_factory=list)
    verdict_rules: list = field(default_factory=list)   # names of the rules that set the verdict (rule_engine.verdict_rule_names)
    nearest_version: str | None = None    # the version asked for is not on PyPI: the nearest one that is (pypi_nearest_version)
    safe_version: str | None = None       # one exact version to use instead of a held one (alternatives.py), from records only

    # [ML] anomaly detection result from the ML model (ml_bridge.ml_predict). None: no ML verdict
    ml: dict | None = None
    package_capabilities: dict | None = None   # what the code can do (package_caps.py), only for flagged packages


@dataclass
class Verdict:
    verdict: str  # ALLOW | NEEDS_HUMAN_REVIEW | BLOCK
    score: float
    reasons: list
    features: ScanFeatures


def fetch_pypi_metadata(name: str) -> dict:
    """Kept for callers outside the guard: sources/pypi.metadata."""
    return pypi.metadata(name)


def fetch_distribution_without_install(name: str, version: str | None, dest_dir: Path,
                                       info: dict | None = None, meta: dict | None = None) -> tuple[str | None, list[Path]]:
    """Kept for callers outside the guard: sources/pypi.fetch."""
    return pypi.fetch(name, version, dest_dir, info, meta)


OSV_MALICIOUS_SKIP = "OSV lists this release as malicious: code analysis skipped (the verdict is BLOCK either way)"


def static_analysis(files: list[Path], features: ScanFeatures, stop=None) -> None:
    """Apply guard/rules/rules.json to the unpacked files (rule_engine.run_static), then the behavior analysis
    (guard/behavior: rebuilt values and data flow, judged by rules/behavior.json). `stop` (a threading.Event, set when
    OSV lists the release as malicious) ends the work early: before each stage, and between files of the behavior
    analysis and between files of the rule pass. Nothing is killed: the analysis returns at the next check."""
    if stop is not None and stop.is_set():
        features.analysis_skipped = OSV_MALICIOUS_SKIP
        return
    rule_engine.run_static(RULESET, files, features, stop=stop)
    if stop is not None and stop.is_set():
        features.analysis_skipped = OSV_MALICIOUS_SKIP
        return
    import behavior
    behavior.analyze(files, features, stop)
    if stop is not None and stop.is_set():
        features.analysis_skipped = OSV_MALICIOUS_SKIP


def _osv_malicious_verdict(features: ScanFeatures) -> Verdict:
    """OSV lists the release as malicious: a BLOCK from the scan itself, so a caller that applies no post rules
    (guard_cli scan) does not show less than the code analysis it skipped would have; the known_malicious post rule
    adds the record's ids and evidence where it runs."""
    from post_rules import malicious_ids
    ids = malicious_ids(features.osv_vulns)
    features.verdict_rules = ["known_malicious"]
    return Verdict("BLOCK", 1.0, [f"OSV lists this release as malicious ({', '.join(ids[:3])})"], features)


def typosquat_check(name: str, features: ScanFeatures) -> None:
    rule_engine.typosquat(RULESET, name, features)


OSV_ECOSYSTEMS = {"pypi": "PyPI", "npm": "npm"}


def query_osv(name: str, version: str | None, ecosystem: str = "pypi") -> list[dict]:
    payload: dict[str, Any] = {"package": {"name": name, "ecosystem": OSV_ECOSYSTEMS.get(ecosystem, ecosystem)}}
    if version:
        payload["version"] = version
    req = urllib.request.Request(
        OSV_QUERY_URL,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with net.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return data.get("vulns", [])
    except Exception:
        return []


def _severity_rank(vulns: list[dict]) -> str | None:
    # OSV's severity[].score is usually a bare CVSS vector string
    # ("CVSS:3.1/AV:N/...") with no literal "CRITICAL"/"HIGH" word in it, so a
    # substring search against it never matches. The actual human-readable
    # rating lives in database_specific.severity for GHSA-sourced advisories -
    # verified directly against OSV's real response for pyyaml 5.3.1
    # (CVE-2020-14343, a real CRITICAL RCE our CRITICAL hard-rule was silently
    # never catching because of this bug).
    order = {"CRITICAL": 3, "HIGH": 2, "MODERATE": 1, "LOW": 0}
    worst = None
    for v in vulns:
        candidates = []
        db_sev = v.get("database_specific", {}).get("severity")
        if db_sev:
            candidates.append(str(db_sev).upper())
        for sev in v.get("severity", []):
            candidates.append(str(sev.get("score", "")).upper())
        for s in candidates:
            for key in order:
                if key in s:
                    if worst is None or order[key] > order[worst]:
                        worst = key
    return worst


# ---------------- scoring (values in guard/rules/scoring.json) ----------------
WEIGHTS = RULESET.weights
TYPOSQUAT_SHORT_NAME_LEN = int(RULESET.sub["typosquat"]["short_name_len"])
BLOCK_THRESHOLD = RULESET.block_threshold
REVIEW_THRESHOLD = RULESET.review_threshold
ML_WEIGHT = RULESET.ml_weight


# [ML] load ml_bridge from this folder and call the ML model. Never raises, whatever fails. The ML model is optional
# (guard_cli.py ml-install): without it, or without ml_bridge.py, the verdict is rule-based only.
def _ml_predict(name, version, handoff=None):
    if not Path(__file__).with_name("ml_bridge.py").exists():
        return {"ok": False, "error": "no ML model installed"}
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("ml_bridge", Path(__file__).with_name("ml_bridge.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.ml_predict(name, version, handoff)
    except Exception as e:
        return {"ok": False, "error": f"ml_bridge error: {type(e).__name__}: {e}"}


def _ml_predict_npm(name, version, pkg_dir):
    """The npm model on an unpacked npm package (ml_bridge.ml_predict_npm). Never raises."""
    if not Path(__file__).with_name("ml_bridge.py").exists():
        return {"ok": False, "error": "no ML model installed"}
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("ml_bridge", Path(__file__).with_name("ml_bridge.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.ml_predict_npm(name, version, pkg_dir)
    except Exception as e:
        return {"ok": False, "error": f"ml_bridge error: {type(e).__name__}: {e}"}


# [ML stage 2] the rule-based verdict, used as is when there is no ML result (failure or AEGIS_ML=0)
def _compute_verdict_rules(features: ScanFeatures) -> Verdict:
    return Verdict(*rule_engine.score_rules(RULESET, features), features)


def _ml_subscore(ml_score: float, threshold: float) -> float:
    return rule_engine.ml_subscore(RULESET, ml_score, threshold)


_VERDICT_RANK = {"ALLOW": 0, "NEEDS_HUMAN_REVIEW": 1, "BLOCK": 2}


def compute_verdict(features: ScanFeatures) -> Verdict:
    """The rules' verdict; with an ML result, the stricter of it and the ML path. The ML path replaces the rules'
    code subscores (entropy, keywords, install hook, reputation) with the ML score, and the model reads its own release
    file (the sdist it was trained on, not always the file pip installs), so on its own it could pass what the rules
    would have stopped: installing the ML model must never weaken a verdict."""
    rules = _compute_verdict_rules(features)
    names = list(getattr(features, "_fired_rules", []))
    ml = features.ml
    if ml and ml.get("ok"):
        with_ml = Verdict(*rule_engine.score_ml(RULESET, features), features)
        key = lambda v: (_VERDICT_RANK.get(v.verdict, 1), v.score)  # noqa: E731
        if key(with_ml) > key(rules):
            names = list(getattr(features, "_fired_ml", [])) or (["ml_score"] if with_ml.verdict != "ALLOW" else [])
            rules = with_ml
    features.verdict_rules = names if rules.verdict != "ALLOW" else []
    return rules



def _hours_since(t: str | None, now: datetime | None = None) -> float | None:
    try:
        when = datetime.fromisoformat(str(t).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, ((now or datetime.now(timezone.utc)) - when).total_seconds() / 3600)


def pypi_nearest_version(meta: dict, wanted: str, hours: float, now: datetime | None = None) -> str | None:
    """A version that is on PyPI, nearest to one that is not: the highest release below it, else the lowest above it;
    not yanked, over `hours` old, a pre-release only when `wanted` is one. None when there is no such release."""
    from _vendor.packaging.version import InvalidVersion, Version
    try:
        want = Version(wanted)
    except InvalidVersion:
        want = None
    now = now or datetime.now(timezone.utc)
    ok = []
    for v, files in (meta.get("releases") or {}).items():
        files = [f for f in files or [] if not f.get("yanked")]
        if not files:
            continue
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if pv.is_prerelease and not (want and want.is_prerelease):
            continue
        times = [f.get("upload_time_iso_8601") for f in files if f.get("upload_time_iso_8601")]
        if times and (now - min(datetime.fromisoformat(t.replace("Z", "+00:00")) for t in times)).total_seconds() < hours * 3600:
            continue
        ok.append((pv, v))
    if not ok:
        return None
    if want is None:
        return max(ok)[1]
    below = [x for x in ok if x[0] < want]
    return max(below)[1] if below else min(ok)[1]


def pypi_release_age_hours(meta: dict, version: str | None, now: datetime | None = None) -> float | None:
    """Hours since the first file of this version was uploaded to PyPI (yanked files ignored), None if unknown."""
    files = [f for f in (meta.get("releases") or {}).get(version or "") or [] if not f.get("yanked")]
    ages = [h for h in (_hours_since(f.get("upload_time_iso_8601"), now) for f in files) if h is not None]
    return max(ages) if ages else None


def _fresh_hours() -> float:
    try:
        return float(rule_engine.current().fresh_release_hours)
    except Exception:
        return 24.0


def pypi_settled_version(meta: dict, resolved: str | None, hours: float, now: datetime | None = None) -> str | None:
    """The newest version below `resolved` whose first file was uploaded at least `hours` ago (yanked files ignored;
    pre-releases only when `resolved` is one). None if there is none. The fresh-release card offers it as the fix."""
    try:
        from _vendor.packaging.version import InvalidVersion, Version
        cur = Version(resolved or "")
    except Exception:
        return None
    best = None
    for v, files in (meta.get("releases") or {}).items():
        try:
            pv = Version(v)
        except InvalidVersion:
            continue
        if pv >= cur or (pv.is_prerelease and not cur.is_prerelease):
            continue
        age = pypi_release_age_hours(meta, v, now)
        if age is None or age < hours:
            continue
        if best is None or pv > best[0]:
            best = (pv, v)
    return best[1] if best else None


def scan_package(name: str, version: str | None = None) -> Verdict:
    """Collection (one PyPI JSON), then the independent lookups run concurrently: the installed file's download and
    static analysis, OSV, the dependency list and (when enabled) the ML model. Verdict logic stays in compute_verdict."""
    from concurrent.futures import ThreadPoolExecutor
    import collect

    features = ScanFeatures(name=name, version=version)
    if COMMAND_STOP.is_set():
        return _command_stopped(features)
    try:
        meta = pypi.metadata(name)
    except Exception as e:
        features.fetch_error = str(e)
        return _removed_release(features, "pypi", version) or \
            Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
    resolved = version or meta.get("info", {}).get("version")
    features.resolved_version = resolved
    if version and not [f for f in (meta.get("releases") or {}).get(version) or [] if not f.get("yanked")]:
        # pip would stop with "no matching distribution": nothing installs. Name the nearest real version instead
        features.nearest_version = pypi_nearest_version(meta, version, _fresh_hours())
        features.fetch_error = f"scan error: HTTP Error 404: version {version} not on PyPI"
        return _removed_release(features, "pypi", version) or \
            Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {features.fetch_error}"], features)
    features.release_age_hours = pypi_release_age_hours(meta, resolved)
    limit = _fresh_hours()
    if features.release_age_hours is not None and features.release_age_hours < limit:
        features.settled_version = pypi_settled_version(meta, resolved, limit)

    ml_artifact_policy = os.environ.get("AEGIS_ML_ARTIFACT", "model")   # "installed": hand the ML model the file we analyze; "model": it picks its own (sdist first)
    rel_box: dict = {}

    def fetch(dest: Path, art: dict) -> list:
        _, files = pypi.fetch(name, version, dest, art, meta)
        features.artifact, features.artifact_kind = art.get("artifact"), art.get("artifact_kind")
        return files

    def release(art: dict, stop) -> None:
        rel_box["rel"] = rel = collect.fetch_release(name, resolved, meta)
        features.requires_dist = list(rel.get("info", {}).get("requires_dist") or [])
        features.dependencies = collect.fetch_requires(name, resolved, meta, rel=rel)

    def ml(art: dict, stop):
        art["release_done"].wait(60)
        if stop.is_set() or "rel" not in rel_box:
            return None if stop.is_set() else {"ok": False, "error": "release information not read"}
        handoff = {"proj": meta, "rel": rel_box["rel"], "artifact": None}
        # the model reads the file it was trained on (sdist first, 20 MB or less); when that is the very file the guard
        # downloads (pip's choice: a release without a fitting wheel), it gets the guard's copy instead of a second
        # download. "installed" hands over the guard's file whatever it is (the features then differ from training).
        same = ml_artifact_policy == "installed" or _ml_file(rel_box["rel"].get("urls") or []) == _guard_file(meta, resolved)
        if same:
            art["fetched"].wait(60)
            if art.get("archive_path"):
                handoff["artifact"] = {"path": art["archive_path"], "filename": art.get("artifact"), "kind": art.get("artifact_kind")}
        return _ml_predict(name, resolved or version, handoff)

    def finish(vulns, ml_result) -> Verdict:
        return _finish(name, meta, features, vulns, ml_result)

    ck = None if _fresh(features) else _cache_key_pypi(name, meta, resolved)
    hit = _from_cache(ck, features, "pypi", resolved)
    if hit is not None:
        return hit
    verdict = _to_cache(ck, _scan_release(features, "pypi", resolved, fetch, release, ml, finish))
    _pick_alternative(features, verdict, "pypi", meta)
    return verdict


ML_MAX_ARTIFACT = 20 * 1024 * 1024   # ml/features.MAX_ARTIFACT


def _ml_file(urls: list) -> str | None:
    """The release file the PyPI model reads (ml/features.pick_artifact: sdist first, 20 MB or less), by name."""
    files = sorted(urls, key=lambda f: f.get("packagetype") != "sdist")
    files = [f for f in files if (f.get("size") or 0) <= ML_MAX_ARTIFACT]
    return os.path.basename(str(files[0].get("filename") or "")) if files else None


def _guard_file(meta: dict, version: str | None) -> str | None:
    """The release file the guard downloads (sources/pypi.fetch: pip's choice), by name; None when unknown."""
    try:
        import artifact_select
        chosen, _kind, _reason = artifact_select.choose((meta.get("releases") or {}).get(version) or [], pypi.ARTIFACT_POLICY)
        return os.path.basename(str(chosen["filename"]).replace("\\", "/")) if chosen else None
    except Exception:
        return None


# One command = one decision: once a package of it is a BLOCK, the whole command is refused, so the other packages'
# scans stop too (guard_core.check_parsed opens and closes the scope of one command). A package stopped that way is a REVIEW that says so,
# never a pass: if a person's allow list later lifts the BLOCK, what was not read still holds the install.
COMMAND_STOP = threading.Event()
COMMAND_STOP_NOTE = "not checked: another package of the same command is blocked"
_COMMAND_ACTIVE = threading.Event()   # only while guard_core decides on one command: a lone scan (guard_cli scan, the
                                      # benchmark, a test) never stops the next one


_COMMAND_DEPTH = [0]                  # a decision can contain another (a plugin's hooks, an MCP launch): the outer one
_COMMAND_LOCK = threading.Lock()      # opens and closes the scope


def command_begin() -> None:
    with _COMMAND_LOCK:
        if _COMMAND_DEPTH[0] == 0:
            COMMAND_STOP.clear()
            _COMMAND_ACTIVE.set()
        _COMMAND_DEPTH[0] += 1


def command_end() -> None:
    with _COMMAND_LOCK:
        _COMMAND_DEPTH[0] = max(0, _COMMAND_DEPTH[0] - 1)
        if _COMMAND_DEPTH[0] == 0:
            _COMMAND_ACTIVE.clear()
            COMMAND_STOP.clear()


def command_blocked() -> None:
    """A package of the command being decided is a BLOCK: the command's other scans stop."""
    if _COMMAND_ACTIVE.is_set():
        COMMAND_STOP.set()


class _Either:
    """is_set() when either event is set (a release's own stop signal, or the command's)."""

    def __init__(self, own, command):
        self.own, self.command = own, command

    def is_set(self) -> bool:
        return self.own.is_set() or self.command.is_set()


def _fresh(features: ScanFeatures) -> bool:
    return features.release_age_hours is None or features.release_age_hours < _fresh_hours()


def _cache_key_pypi(name: str, meta: dict, version: str | None) -> str | None:
    """verdict_cache key of the file pip installs for this version (its name and SHA-256: wheel and sdist apart)."""
    try:
        import artifact_select
        import verdict_cache
        chosen, _kind, _reason = artifact_select.choose((meta.get("releases") or {}).get(version) or [], pypi.ARTIFACT_POLICY)
        sha = ((chosen or {}).get("digests") or {}).get("sha256")
        fid = f"{os.path.basename(str(chosen['filename']))}:{sha}" if chosen and sha else None
        return verdict_cache.key("pypi", name, version, fid)
    except Exception:
        return None


def _cache_key_npm(name: str, meta: dict, version: str | None) -> str | None:
    """verdict_cache key of an npm version: its tarball's integrity hash from the registry."""
    try:
        import verdict_cache
        dist = (((meta.get("versions") or {}).get(version) or {}).get("dist") or {})
        return verdict_cache.key("npm", name, version, dist.get("integrity"))
    except Exception:
        return None


def _from_cache(ck: str | None, features: ScanFeatures, ecosystem: str, version: str | None) -> Verdict | None:
    """A cached ALLOW for exactly this file, when OSV still has no record of the version (asked again every time);
    None means: scan it."""
    if not ck:
        return None
    try:
        import verdict_cache
        cached = verdict_cache.get(ck)
    except Exception:
        return None
    if cached is None:
        return None
    vulns = query_osv(features.name, version, ecosystem)
    if vulns:
        return None                                   # reported since: scanned again (a BLOCK when malicious)
    f = cached.features
    f.osv_vulns, f.osv_max_severity = [], None
    f.release_age_hours = features.release_age_hours    # the hour-dependent facts of now, not of the cached scan
    f.from_cache = True
    return cached


def _to_cache(ck: str | None, verdict: Verdict) -> Verdict:
    if ck:
        try:
            import verdict_cache
            verdict_cache.put(ck, verdict)
        except Exception:
            pass
    return verdict


def _removed_release(features: ScanFeatures, ecosystem: str, version: str | None) -> Verdict | None:
    """A release the registry no longer has (often removed after a malware report): the OSV BLOCK when OSV lists the
    exact version asked for as malicious, else None (the caller's "could not fetch" stands)."""
    if not version or not re.fullmatch(r"[0-9A-Za-z.+!_-]{1,64}", str(version)):
        return None                                   # a range or a tag: no single version to ask OSV about
    try:
        from post_rules import malicious_ids
        vulns = query_osv(features.name, version, ecosystem)
        if not malicious_ids(vulns):
            return None
    except Exception:
        return None
    features.osv_vulns, features.osv_max_severity = vulns, _severity_rank(vulns)
    features.resolved_version = features.resolved_version or version
    features.analysis_skipped = OSV_MALICIOUS_SKIP
    return _block_command(_osv_malicious_verdict(features))


def _command_stopped(features: ScanFeatures) -> Verdict:
    features.command_stopped = True
    features.analysis_skipped = COMMAND_STOP_NOTE
    features.fetch_error = features.fetch_error or COMMAND_STOP_NOTE
    return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [COMMAND_STOP_NOTE], features)


def _block_command(verdict: Verdict) -> Verdict:
    if verdict.verdict == "BLOCK":
        command_blocked()
    return verdict


OSV_WAIT_FOR_ML = 20.0       # seconds the ML stage waits for OSV's answer; after that it runs anyway


def _scan_release(features: ScanFeatures, ecosystem: str, version: str | None, fetch, release, ml, finish) -> Verdict:
    """The scan of one registry release, the same for PyPI and npm (what differs is passed in):

        [download -> rules -> behavior analysis]  [release info -> dependency list]  [OSV]  [ML model]   at the same time
        -> the verdict (rules, then the ML path; the stricter one) -> what the code can do, for a held package

    OSV listing the release as malicious sets a stop signal: the download stops within 1 MB, the rule pass and the
    behavior analysis at their next file, the ML model is not started, and the verdict is that BLOCK.
      fetch(dest, art) -> files         download and unpack into dest (never run); fills art (archive_path, root, ...)
      release(art, stop)                release info and dependency list; a failure is recorded, never decides
      ml(art, stop) -> dict | None      the ML result (None: not run); started after OSV answers, waits for
                                        art["fetched"] / art["release_done"] itself
      finish(vulns, ml_result)          the verdict from the features
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor
    art: dict = {"fetched": threading.Event(), "release_done": threading.Event(), "osv_done": threading.Event(),
                 "archive_ready": None}
    art["archive_ready"] = art["fetched"]            # sources/pypi.fetch sets it as soon as the archive is on disk
    if COMMAND_STOP.is_set():                        # another package of this command is already a BLOCK
        return _command_stopped(features)
    own = threading.Event()                          # set when OSV lists this release as malicious: BLOCK is certain
    stop = _Either(own, COMMAND_STOP)                # what every stage checks: this release, or the whole command
    art["stop"] = stop                               # the download checks it every 1 MB (net.read_capped)

    def osv_task():
        try:
            vulns = query_osv(features.name, version, ecosystem)
            try:
                from post_rules import malicious_ids
                if malicious_ids(vulns):
                    own.set()
            except Exception:
                pass                                  # unsure: the full analysis runs as before
            return vulns
        finally:
            art["osv_done"].set()

    def ml_task():
        # the model starts only after OSV has answered (median 0.6 s): a release OSV lists as malicious never runs it,
        # whichever of OSV and the release info arrives first
        art["osv_done"].wait(OSV_WAIT_FOR_ML)
        if stop.is_set():
            return None
        return ml(art, stop)
    tmp = tempfile.TemporaryDirectory()              # outlives the pool: the ML process may still be reading the files

    def artifact_task():
        try:
            files = fetch(Path(tmp.name), art)
            art["files"] = files
            features.skipped_members = list(art.get("skipped", []))
        finally:
            art["fetched"].set()                     # never leave the ML stage waiting
        static_analysis(files, features, stop)

    def release_task():
        try:
            if release is not None:
                release(art, stop)
        finally:
            art["release_done"].set()

    try:
        with ThreadPoolExecutor(4) as pool:
            art_f = pool.submit(artifact_task)
            rel_f = pool.submit(release_task)
            osv_f = pool.submit(osv_task)
            ml_f = pool.submit(ml_task) if ml is not None else None
            try:
                art_f.result()
                features.fetch_ok = True
            except Exception as e:
                features.fetch_error = str(e)
            try:
                rel_f.result()
            except Exception as e:
                features.deps_error = str(e)               # unknown dependency list: reported, never blocks the verdict
            vulns = osv_f.result()
            try:
                ml_result = ml_f.result() if ml_f is not None else None
            except Exception as e:
                ml_result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
        if own.is_set():                           # OSV lists it as malicious (also when the download failed:
            features.osv_vulns = vulns             # often removed from the registry by then)
            features.osv_max_severity = _severity_rank(vulns)
            features.analysis_skipped = OSV_MALICIOUS_SKIP
            return _block_command(_osv_malicious_verdict(features))
        if features.fetch_error:
            features.osv_vulns = vulns
            if COMMAND_STOP.is_set():
                return _command_stopped(features)
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {features.fetch_error}"], features)
        verdict = finish(vulns, ml_result)
        if COMMAND_STOP.is_set() and verdict.verdict != "BLOCK":
            return _command_stopped(features)      # stopped part way: what was read is no verdict
        _block_command(verdict)
        if verdict.verdict != "ALLOW" and art.get("files"):
            try:                                   # what the code can do, for the attack paths (never part of the verdict)
                import package_caps
                features.package_capabilities = package_caps.extract(art["files"], install_files=features.install_time_files)
            except Exception as e:
                features.package_capabilities = {"items": [], "counts": {}, "files": 0, "limits": [f"analysis failed: {type(e).__name__}"]}
        return verdict
    finally:
        tmp.cleanup()


def _pick_alternative(features: ScanFeatures, verdict: Verdict, ecosystem: str, meta: dict, times=None) -> None:
    """features.safe_version when another version of the same package is the answer: a vulnerability, a release under a
    day old, or an OSV malicious record (a hijacked release; a package that is malicious in every version has no clean
    one). alternatives.py. Never raises and never changes the verdict."""
    try:
        fresh = features.release_age_hours is not None and features.release_age_hours < _fresh_hours()
        if not features.osv_vulns and not fresh:
            return                                     # code findings, ML, a name: another version of it is no answer
        import alternatives
        from post_rules import malicious_ids
        fix = None
        if features.osv_vulns and not malicious_ids(features.osv_vulns):
            fix = alternatives.fix_version_of(features.osv_vulns, features.resolved_version)
            if fix is None:
                return                                 # a vulnerability no version fixes: nothing to name
        cur = features.resolved_version or features.version
        if ecosystem == "npm":
            times = times() if callable(times) else times      # the full document: fetched only for a held package
            features.safe_version = alternatives.npm(features.name, meta, times, cur, fix, _fresh_hours())
        else:
            features.safe_version = alternatives.pypi(features.name, meta, cur, fix, _fresh_hours())
    except Exception:
        features.safe_version = None


def local_name_version(path: Path) -> tuple[str, str | None]:
    """(name, version) from a wheel or sdist file name: `corp_utils-1.4.2-py3-none-any.whl`, `corp-utils-1.4.2.tar.gz`."""
    base = path.name
    if base.endswith(".whl"):
        parts = base[:-4].split("-")
        return parts[0].replace("_", "-"), (parts[1] if len(parts) > 1 else None)
    stem = re.sub(r"\.(tar\.gz|tgz|tar\.bz2|zip)$", "", base)
    m = re.match(r"^(.+?)-(\d[\w.!+]*)$", stem)
    return (m.group(1), m.group(2)) if m else (stem, None)


def scan_local_file(path: str | Path) -> Verdict:
    """A wheel or sdist already on disk (`pip install ./x.whl`), scanned like a PyPI release but without PyPI: the file
    is unpacked (never run) and only the code rules apply. Name-based checks (typosquat, new package, OSV, reputation,
    version history) are about PyPI's project of that name, which is not what is installed here, so they are left out."""
    path = Path(path)
    name, version = local_name_version(path)
    features = ScanFeatures(name=name, version=version, resolved_version=version)
    features.artifact = path.name
    features.artifact_kind = "wheel" if path.name.endswith(".whl") else "sdist"
    with tempfile.TemporaryDirectory() as tmp:
        try:
            if path.stat().st_size > MAX_DOWNLOAD_BYTES:
                raise ValueError(f"package file too large, code not scanned (>{MAX_DOWNLOAD_BYTES // 1024 // 1024}MB limit)")
            raw = path.read_bytes()
            root = Path(tmp) / (path.name + ".unpacked")
            root.mkdir()
            skipped: list = []
            aside = None if path.name.endswith(".whl") else safe_extract.aside_dir(root)    # see sources/pypi.fetch
            if path.name.endswith((".whl", ".zip")):
                safe_extract.extract_zip(raw, root, skipped, aside=aside)
            elif path.name.endswith((".tar.gz", ".tgz")):
                safe_extract.extract_targz(raw, root, skipped, aside=aside)
            else:
                raise ValueError("cannot unpack a package file of this format")
            files = list(root.rglob("*"))
            features.skipped_members = skipped
        except Exception as e:
            features.fetch_error = str(e)
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
        return scan_files(files, features)


def scan_files(files: list[Path], features: ScanFeatures) -> Verdict:
    """The source-independent part of a scan: rules over files already on disk (features.ecosystem says which languages
    are code), the verdict, and - for a flagged package - what its code can do (attack paths; Python code only for now).
    Registry packages (PyPI, npm) go through _scan_release instead; local files, git / URL sources and bundles end here."""
    static_analysis(files, features)
    features.fetch_ok = True
    verdict = compute_verdict(features)
    if verdict.verdict != "ALLOW":
        try:
            import package_caps
            features.package_capabilities = package_caps.extract(files, install_files=features.install_time_files)
        except Exception as e:
            features.package_capabilities = {"items": [], "counts": {}, "files": 0, "limits": [f"analysis failed: {type(e).__name__}"]}
    return verdict


def scan_npm_package(name: str, spec: str | None = None) -> Verdict:
    """An npm registry package (sources/npm.py): the version npm would install, its tarball and lifecycle scripts
    through the rules, OSV's npm records and the npm ML model, in the same pipeline as PyPI (_scan_release). PyPI-only
    checks (typosquat list, PyPI reputation, version history) are not applied; OSV's malicious-release records are
    (post_rules known_malicious, via features.osv_vulns)."""
    from sources import npm
    features = ScanFeatures(name=name, version=spec, ecosystem="npm")
    if COMMAND_STOP.is_set():
        return _command_stopped(features)
    try:
        meta = npm.metadata(name)
        version = npm.pick_version(meta, spec)
        if version is None:
            raise ValueError(f"no version on npm matches '{name}@{spec or 'latest'}'")
    except Exception as e:
        features.fetch_error = str(e)
        return _removed_release(features, "npm", spec) or \
            Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
    features.version = features.resolved_version = version
    try:
        features.release_age_hours = npm.release_age_hours(name, version, meta)
    except Exception:
        features.release_age_hours = None                 # unknown: the fresh-release rule does not apply
    limit = _fresh_hours()
    if features.release_age_hours is not None and features.release_age_hours < limit:
        try:
            features.settled_version = npm.settled_version(name, spec, version, meta, limit)
        except Exception:
            features.settled_version = None

    def fetch(dest: Path, art: dict) -> list:
        _, files = npm.fetch(name, version, dest, meta, art)
        features.artifact, features.artifact_kind = art.get("artifact"), "npm"
        features.install_time_files = npm.install_time_files(files)
        return files

    def release(art: dict, stop) -> None:
        doc = (meta.get("versions") or {}).get(version) or {}
        deps = {}
        for key in ("dependencies", "optionalDependencies"):
            if isinstance(doc.get(key), dict):
                deps.update(doc[key])
        features.dependencies = [{"name": n, "spec": str(v), "extras": []} for n, v in sorted(deps.items())]

    def ml(art: dict, stop):
        art["fetched"].wait(120)
        if stop.is_set() or not art.get("root"):
            return None                           # OSV already decided, or nothing unpacked: no model run
        return _ml_predict_npm(name, version, art["root"])

    def finish(vulns, ml_result) -> Verdict:
        features.osv_vulns = vulns
        features.osv_max_severity = _severity_rank(vulns)
        features.ml = ml_result
        return compute_verdict(features)

    ck = None if _fresh(features) else _cache_key_npm(name, meta, version)
    hit = _from_cache(ck, features, "npm", version)
    if hit is not None:
        return hit
    verdict = _to_cache(ck, _scan_release(features, "npm", version, fetch, release, ml, finish))
    _pick_alternative(features, verdict, "npm", meta, lambda: _npm_times(npm, name))
    return verdict


def _npm_times(npm, name: str):
    try:
        return npm._publish_times(name)
    except Exception:
        return None


def _as_package_root(root: Path, tmp: Path) -> Path:
    """A repository checkout's package folder moved to `<tmp>/git.unpacked/pkg`, laid out like an sdist: every path is
    then judged from the package root, so `#subdirectory=tests` does not make each file a test file. The files kept
    aside next to the archive (safe_extract.aside_dir) move along."""
    twin = None
    for i, part in enumerate(root.parts):
        if part.endswith(".unpacked"):
            twin = safe_extract.aside_dir(Path(*root.parts[:i + 1])).joinpath(*root.parts[i + 1:])
            break
    new = tmp / "git.unpacked" / "pkg"
    new.parent.mkdir(parents=True, exist_ok=True)
    os.rename(root, new)
    if twin is not None and twin.is_dir():
        side = safe_extract.aside_dir(new.parent) / "pkg"
        side.parent.mkdir(parents=True, exist_ok=True)
        os.rename(twin, side)
    return new


def scan_direct(src: dict) -> Verdict:
    """A package installed from a git repository or a URL (sources/direct.py): the same code the installer would fetch,
    read with the rules of its ecosystem. For npm the install scripts are read too, and `prepare` - npm runs it when it
    installs from git. Only the code is checked (see scan_local_file)."""
    from sources import direct, npm
    eco = src.get("ecosystem") or "pypi"
    if src["kind"] == "archive" and eco == "pypi":
        with tempfile.TemporaryDirectory() as tmp:
            try:
                path = direct.download(src, Path(tmp))
            except Exception as e:
                features = ScanFeatures(name=src.get("name") or src["url"], version=None)
                features.fetch_error = str(e)
                return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
            verdict = scan_local_file(path)
            verdict.features.artifact = direct.shown(src)
            return verdict
    features = ScanFeatures(name=src.get("name") or src["url"], version=src.get("ref"), ecosystem=eco)
    features.artifact, features.artifact_kind = direct.shown(src), src["kind"]
    with tempfile.TemporaryDirectory() as tmp:
        try:
            if src["kind"] == "git":
                root = direct.checkout(src, Path(tmp))
                if eco == "pypi":
                    root = _as_package_root(root, Path(tmp))
                files = [f for f in root.rglob("*") if f.is_file()]
            else:                                          # an npm tarball URL
                path = direct.download(src, Path(tmp))
                root = Path(tmp) / "pkg.unpacked"
                root.mkdir()
                skipped: list = []
                files = npm.extract(path.read_bytes(), root, skipped)
                features.skipped_members = skipped
            if eco == "npm":
                events = npm.LIFECYCLE + (("prepare",) if src["kind"] == "git" else ())
                features.install_time_files = npm.install_time_files(files, events)
                files += npm.write_lifecycle(files, Path(tmp), "direct", events)
        except Exception as e:
            features.fetch_error = str(e)
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
        return scan_files(files, features)


def scan_npm_scripts(name: str, texts: dict) -> Verdict:
    """A project's own npm install scripts (a bare `npm install` runs them: npm_parse) and what they run, already read
    into `package.json#<event>...` texts (sources/npm.run_texts): read like the install scripts of an npm package."""
    features = ScanFeatures(name=name, version=None, ecosystem="npm")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "project.scripts.unpacked"
        out.mkdir()
        files = []
        for fname, text in texts.items():
            f = out / Path(fname).name
            f.write_text(text)
            files.append(f)
        return scan_files(files, features)


def scan_bundle(name: str, paths: list, texts: dict | None = None, kind: str | None = None) -> Verdict:
    """Files already on disk - a skill, a plugin, a hook script, a local MCP server script (sources/bundle.py) - read
    with the "bundle" ecosystem: every language is code, nothing is skipped. texts: text that is not a file (a hook's
    command line), scanned as a file of its own. kind: what the agent runs by itself is read like install-time code
    (a hook's commands and scripts, an MCP server's script; in a plugin, its hook command lines and the files they
    name), the rest like code that runs only when called."""
    from sources import bundle
    features = ScanFeatures(name=name, version=None, ecosystem="bundle")
    with tempfile.TemporaryDirectory() as tmp:
        try:
            files, notes = bundle.copy_into(paths, Path(tmp), name, texts)
        except Exception as e:
            features.fetch_error = str(e)
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
        features.install_time_files = bundle.auto_run(files, kind, texts)
        verdict = scan_files(files, features)
        verdict.reasons.extend(notes)
        return verdict


# the scan function of each ecosystem other than PyPI (guard_core dispatches Parsed.ecosystem_packages through this)
ECOSYSTEM_SCANNERS = {"npm": scan_npm_package}


def _finish(name: str, meta: dict, features: "ScanFeatures", vulns: list, ml_result) -> "Verdict":
    import collect
    typosquat_check(name, features)
    rep = collect.reputation_signals(meta)
    features.maintainer_count = rep["maintainer_count"]
    features.has_readme = features.has_readme or rep["has_description"]
    features.package_age_days = rep["age_days"]

    features.osv_vulns = vulns
    features.osv_max_severity = _severity_rank(vulns)
    # [ML] anomaly detection result. If it failed, the rule-based verdict goes ahead as is
    features.ml = ml_result

    return compute_verdict(features)


SCAN_BUDGET_SECONDS = 540     # whole-command budget; the hook's own timeout is set above this
SCAN_WORKERS = 4


def scan_packages(items: list[tuple[str, str | None]], budget: float = SCAN_BUDGET_SECONDS,
                  workers: int = SCAN_WORKERS) -> list[Verdict]:
    """Scan several packages in parallel under one time budget (a requirements file can hold
    dozens). A package not finished in time gets a NEEDS_HUMAN_REVIEW verdict saying so rather
    than being dropped: the hook is fail-open on timeout, so running out of time must be visible.
    Worker threads are daemons, so a stuck download never keeps the hook process alive."""
    import queue
    import threading
    import time

    results: list[Verdict | None] = [None] * len(items)
    todo: queue.Queue = queue.Queue()
    for idx, item in enumerate(items):
        todo.put((idx, item))

    def worker() -> None:
        while True:
            try:
                idx, (name, version) = todo.get_nowait()
            except queue.Empty:
                return
            try:
                results[idx] = scan_package(name, version)
            except Exception as e:  # a crash is a finding, not a pass
                f = ScanFeatures(name=name, version=version, fetch_error=f"scan error: {e}")
                results[idx] = Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"scan error: {e}"], f)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(max(1, min(workers, len(items))))]
    for t in threads:
        t.start()
    deadline = time.monotonic() + budget
    for t in threads:
        t.join(max(0.0, deadline - time.monotonic()))
    out: list[Verdict] = []
    for (name, version), r in zip(items, results):
        if r is None:
            f = ScanFeatures(name=name, version=version, fetch_error=f"scan timed out ({budget:.0f}s)")
            r = Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"scan timed out ({budget:.0f}s) - not checked"], f)
        out.append(r)
    return out


if __name__ == "__main__":
    import sys

    pkg = sys.argv[1] if len(sys.argv) > 1 else "requests"
    ver = sys.argv[2] if len(sys.argv) > 2 else None
    result = scan_package(pkg, ver)
    print(json.dumps({
        "verdict": result.verdict,
        "score": result.score,
        "reasons": result.reasons,
    }, ensure_ascii=False, indent=2))
