"""
AegisPilot - Skill/Hook self-integrity check.

Computes sha256 of the guard's own files and compares against a manifest.
The manifest is created automatically on first use (no "install step" - the
first time a PreToolUse(Bash) install checkpoint fires, if no manifest
exists yet, the current state is trusted and recorded as the baseline).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GUARD_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = GUARD_DIR / "aasm_manifest.json"

# the files whose integrity matters: the hooks themselves, the scan/guard
# modules they import, and the Skill definition. If any of these is missing
# or changed, the guard may no longer behave as installed. Hooks fail open, so
# a broken file is as dangerous as a disabled hook.
PROTECTED_FILES = [
    "hooks/pretooluse_check.py",
    "hooks/pretooluse_editwrite_check.py",
    "scan_engine.py",
    "review_report.py",
    "install_parse.py",
    "index_config.py",
    "npm_parse.py",
    "sources/__init__.py",
    "sources/npm.py",
    "transitive.py",
    "package_caps.py",
    "rule_modules.py",
    "profile/__init__.py",
    "profile/analyzer.py",
    "hook_runtime.py",
    "remote_wheel.py",
    "safe_extract.py",
    "artifact_select.py",
    "collect.py",
    "ml_bridge.py",
    "r4/mvp_output.py",
    "mode.py",
    "r4/text_format.py",
    "r3/r3_scan.py",
    "r3/r3_features.py",
    "r3/code_features.py",
    "guard_paths.py",
    "install_state.py",
    "guard_core.py",
    "policy.py",
    "project_deps.py",
    "scan_parallel.py",
    "verdict_cache.py",
    "post_rules.py",
    "version_diff.py",
    "env_profile.py",
    "project_code.py",
    "attack_path.py",
    "adapters/__init__.py",
    "adapters/claude_code.py",
    "adapters/codex.py",
    "hooks/codex_pretooluse.py",
    "mcp_guard.py",
    "mcp_scan.py",
    "plugin_scan.py",
    "hook_scan.py",
    "agent_config.py",
    "agent_formats.json",
    "sources/repo.py",
    "sources/bundle.py",
    "sources/direct.py",
    "sources/pypi.py",
    "checks/__init__.py",
    "checks/base.py",
    "checks/pypi.py",
    "checks/local_files.py",
    "checks/direct.py",
    "checks/ecosystems.py",
    "checks/bundles.py",
    "checks/npm.py",
    "checks/unscanned.py",
    "integrity.py",
    "repair.py",
    "switches.py",
    "acks.py",
    "index_trust.py",
    "system_install.py",
    "rule_engine.py",
    "behavior/__init__.py",
    "behavior/values.py",
    "behavior/shell.py",
    "behavior/python.py",
    "behavior/js.py",
    "rules/behavior.json",
    "rules/signals.json",
    "rules/rules.json",
    "rules/scoring.json",
    "rules/post.json",
    "rules/capabilities.json",
    "skills/aegis/SKILL.md",
]


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _current_hashes() -> dict[str, str | None]:
    return {rel: _sha256(GUARD_DIR / rel) for rel in PROTECTED_FILES}


RELEASE_MANIFEST = GUARD_DIR / "RELEASE_MANIFEST.json"
BUILD_INFO = GUARD_DIR / "BUILD_INFO.json"
# a file of these kinds appearing in the guard folder is a finding: Python imports from it (a json.py next to the hooks
# would shadow the standard library), reads it as rules, or runs it at start (.pth)
_EXTRA_KINDS = (".py", ".pth", ".json", ".pyc")


def released() -> bool:
    """A built guard (scripts/build_dist.py) - as opposed to a development checkout."""
    return BUILD_INFO.exists()


def check_release(root: Path = GUARD_DIR) -> list[str]:
    """A built guard against the checksums recorded at build time (RELEASE_MANIFEST.json): changed, deleted and added
    files. A missing or unreadable manifest is a finding - it is never re-created from what is on disk."""
    try:
        files = json.loads((root / "RELEASE_MANIFEST.json").read_text())["files"]
        assert isinstance(files, dict) and files
    except (OSError, ValueError, KeyError, TypeError, AssertionError):
        return ["checksum list (RELEASE_MANIFEST.json) missing or unreadable - the build-time baseline is gone"]
    findings = []
    for rel, expected in files.items():
        actual = _sha256(root / rel)
        if actual is None:
            findings.append(f"{rel} was deleted")
        elif actual != expected:
            findings.append(f"{rel} checksum differs from install time (possible tampering)")
    for f in sorted(root.rglob("*")):
        rel = f.relative_to(root)
        if not f.is_file() or str(rel) in files or str(rel) in ("RELEASE_MANIFEST.json", MANIFEST_PATH.name):
            continue
        if "__pycache__" in rel.parts and f.suffix == ".pyc":
            continue        # Python's own cache (see the README on how hooks run: python3 -I)
        if f.suffix.lower() in _EXTRA_KINDS:
            findings.append(f"{rel} was added after install (possible tampering)")
    return findings


def check_integrity() -> list[str]:
    """Returns a list of human-readable mismatch descriptions (empty = clean).

    A built guard is checked against the checksums made at build time (check_release). A development checkout keeps
    the old trust-on-first-use manifest: the first call creates it from the current state and returns no findings.
    """
    if released():
        return check_release()
    current = _current_hashes()

    if not MANIFEST_PATH.exists():
        MANIFEST_PATH.write_text(json.dumps(current, indent=2, ensure_ascii=False))
        return []

    try:
        manifest = json.loads(MANIFEST_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        # manifest itself is unreadable/corrupted - that's a finding too.
        MANIFEST_PATH.write_text(json.dumps(current, indent=2, ensure_ascii=False))
        return ["integrity manifest was corrupted (regenerated)"]

    findings = []
    for rel, expected in manifest.items():
        actual = current.get(rel)
        if actual is None and expected is not None:
            findings.append(f"{rel} was deleted")
        elif actual != expected:
            findings.append(f"{rel} checksum differs from install time (possible tampering)")
    return findings
