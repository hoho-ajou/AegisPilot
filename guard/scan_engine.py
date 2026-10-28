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

import io
import json
import os
import re
import tarfile
import tempfile
import urllib.request
import warnings
import zipfile
from dataclasses import dataclass, field
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
    dependencies: list = field(default_factory=list)   # direct deps that apply to a plain install [{name, spec}]
    deps_error: str | None = None

    min_edit_distance: int | None = None
    closest_popular_name: str | None = None

    osv_vulns: list = field(default_factory=list)
    osv_max_severity: str | None = None

    maintainer_count: int | None = None
    package_age_days: float | None = None
    has_readme: bool = False

    # [{rule, file, line, snippet, ...}] - rules: decode_then_exec,
    # download_then_execute, install_hook, high_entropy, keyword
    evidence: list = field(default_factory=list)

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


def static_analysis(files: list[Path], features: ScanFeatures) -> None:
    """Apply guard/rules/rules.json to the unpacked files (rule_engine.run_static), then the behavior analysis
    (guard/behavior: rebuilt values and data flow, judged by rules/behavior.json)."""
    rule_engine.run_static(RULESET, files, features)
    import behavior
    behavior.analyze(files, features)


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
        with urllib.request.urlopen(req, timeout=15) as resp:
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
# and not part of every install: without ml_bridge.py the verdict is rule-based only.
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


# [ML stage 2] the rule-based verdict, used as is when there is no ML result (failure or AEGIS_ML=0)
def _compute_verdict_rules(features: ScanFeatures) -> Verdict:
    return Verdict(*rule_engine.score_rules(RULESET, features), features)


def _ml_subscore(ml_score: float, threshold: float) -> float:
    return rule_engine.ml_subscore(RULESET, ml_score, threshold)


def compute_verdict(features: ScanFeatures) -> Verdict:
    ml = features.ml
    if not (ml and ml.get("ok")):
        return _compute_verdict_rules(features)   # no ML: the rules alone
    return Verdict(*rule_engine.score_ml(RULESET, features), features)



def scan_package(name: str, version: str | None = None) -> Verdict:
    """Collection (one PyPI JSON), then the independent lookups run concurrently: the installed file's download and
    static analysis, OSV, the dependency list and (when enabled) the ML model. Verdict logic stays in compute_verdict."""
    from concurrent.futures import ThreadPoolExecutor
    import collect

    features = ScanFeatures(name=name, version=version)
    try:
        meta = pypi.metadata(name)
    except Exception as e:
        features.fetch_error = str(e)
        return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
    resolved = version or meta.get("info", {}).get("version")
    features.resolved_version = resolved

    import threading

    ml_artifact_policy = os.environ.get("AEGIS_ML_ARTIFACT", "model")   # "installed": hand the ML model the file we analyze; "model": it picks its own (sdist first)
    art: dict = {"archive_ready": threading.Event()}
    tmp = tempfile.TemporaryDirectory()          # outlives the pool: the ML process may still be reading the archive

    def artifact_task():
        try:
            _, files = pypi.fetch(name, version, Path(tmp.name), art, meta)
            art["files"] = files
            features.artifact, features.artifact_kind = art.get("artifact"), art.get("artifact_kind")
            features.skipped_members = list(art.get("skipped", []))
            static_analysis(files, features)
        finally:
            art["archive_ready"].set()           # never leave the ML stage waiting (Range path / failure leave no archive)

    def rel_task():
        return collect.fetch_release(name, resolved, meta)

    def deps_task(rel_f):
        features.dependencies = collect.fetch_requires(name, resolved, meta, rel=rel_f.result())

    def ml_task(rel_f):
        rel = rel_f.result()
        handoff = {"proj": meta, "rel": rel, "artifact": None}
        if ml_artifact_policy == "installed":
            art["archive_ready"].wait(60)
            if art.get("archive_path"):
                handoff["artifact"] = {"path": art["archive_path"], "filename": art.get("artifact"), "kind": art.get("artifact_kind")}
        return _ml_predict(name, resolved or version, handoff)

    try:
        with ThreadPoolExecutor(5) as pool:
            art_f = pool.submit(artifact_task)
            rel_f = pool.submit(rel_task)
            deps_f = pool.submit(deps_task, rel_f)
            osv_f = pool.submit(query_osv, name, resolved)
            ml_f = pool.submit(ml_task, rel_f)
            try:
                art_f.result()
                features.fetch_ok = True
            except Exception as e:
                features.fetch_error = str(e)
            try:
                deps_f.result()
            except Exception as e:
                features.deps_error = str(e)               # unknown dependency list: reported, never blocks the verdict
            vulns = osv_f.result()
            ml_result = ml_f.result()
        if features.fetch_error:
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {features.fetch_error}"], features)
        verdict = _finish(name, meta, features, vulns, ml_result)
        if verdict.verdict != "ALLOW" and art.get("files"):
            try:                                   # what the code can do, for the attack paths (never part of the verdict)
                import package_caps
                features.package_capabilities = package_caps.extract(art["files"])
            except Exception as e:
                features.package_capabilities = {"items": [], "counts": {}, "files": 0, "limits": [f"analysis failed: {type(e).__name__}"]}
        return verdict
    finally:
        tmp.cleanup()


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
            if path.name.endswith((".whl", ".zip")):
                safe_extract.extract_zip(raw, root, skipped)
            elif path.name.endswith((".tar.gz", ".tgz")):
                safe_extract.extract_targz(raw, root, skipped)
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
    Every source (PyPI's scan_package keeps its own concurrent flow; local files, npm, bundles) ends here."""
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
    through the rules, and OSV's npm records. PyPI-only checks (typosquat list, PyPI reputation, version history) are
    not applied; OSV's malicious-release records are (post_rules known_malicious, via features.osv_vulns)."""
    from sources import npm
    features = ScanFeatures(name=name, version=spec, ecosystem="npm")
    try:
        meta = npm.metadata(name)
        version = npm.pick_version(meta, spec)
        if version is None:
            raise ValueError(f"no version on npm matches '{name}@{spec or 'latest'}'")
    except Exception as e:
        features.fetch_error = str(e)
        return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
    features.version = features.resolved_version = version
    from concurrent.futures import ThreadPoolExecutor
    with tempfile.TemporaryDirectory() as tmp, ThreadPoolExecutor(1) as pool:
        osv_f = pool.submit(query_osv, name, version, "npm")
        try:
            info: dict = {}
            _, files = npm.fetch(name, version, Path(tmp), meta, info)
            features.artifact, features.artifact_kind = info.get("artifact"), "npm"
            features.skipped_members = list(info.get("skipped", []))
            features.install_time_files = npm.install_time_files(files)
        except Exception as e:
            features.fetch_error = str(e)
            features.osv_vulns = osv_f.result()
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
        features.osv_vulns = osv_f.result()
        features.osv_max_severity = _severity_rank(features.osv_vulns)
        return scan_files(files, features)


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
                files = [f for f in root.rglob("*") if f.is_file()]
            else:                                          # an npm tarball URL
                path = direct.download(src, Path(tmp))
                root = Path(tmp) / "pkg.unpacked"
                root.mkdir()
                skipped: list = []
                safe_extract.extract_targz(path.read_bytes(), root, skipped, npm.KEEP_SUFFIXES)
                features.skipped_members = skipped
                files = list(root.rglob("*"))
            if eco == "npm":
                features.install_time_files = npm.install_time_files(
                    files, npm.LIFECYCLE + (("prepare",) if src["kind"] == "git" else ()))
                files += npm.write_lifecycle(files, Path(tmp), "direct")
                pkg = [f for f in files if f.name == "package.json"]
                if src["kind"] == "git" and pkg:
                    try:
                        doc = json.loads(min(pkg, key=lambda f: len(f.parts)).read_text(errors="replace"))
                        prepare = (doc.get("scripts") or {}).get("prepare")
                    except (OSError, ValueError, AttributeError):
                        prepare = None
                    if isinstance(prepare, str) and prepare.strip():
                        f = Path(tmp) / "direct.scripts.unpacked" / "package.json#prepare.sh"
                        f.parent.mkdir(parents=True, exist_ok=True)
                        f.write_text(prepare + "\n")
                        files.append(f)
        except Exception as e:
            features.fetch_error = str(e)
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
        return scan_files(files, features)


def scan_bundle(name: str, paths: list, texts: dict | None = None) -> Verdict:
    """Files already on disk - a skill, a plugin, a hook script, a local MCP server script (sources/bundle.py) - read
    with the "bundle" ecosystem: every language is code, nothing is skipped. texts: text that is not a file (a hook's
    command line), scanned as a file of its own."""
    from sources import bundle
    features = ScanFeatures(name=name, version=None, ecosystem="bundle")
    with tempfile.TemporaryDirectory() as tmp:
        try:
            files, notes = bundle.copy_into(paths, Path(tmp), name, texts)
        except Exception as e:
            features.fetch_error = str(e)
            return Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"fetch/analysis failed: {e}"], features)
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
