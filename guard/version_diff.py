"""
AegisPilot - what is NEW in this release compared with the one before it.

A project that has been fine for years and is then taken over (stolen token, poisoned CI) ships its next release with
an added payload. Its age, name and reputation all look trustworthy, and OSV has no record yet. Measured on the 29
compromised releases of 17 real projects in the DataDog dataset (samples/pypi/compromised_lib: litellm, ultralytics,
num2words, telnyx, xinference, durabletask, guardrails-ai, ...): the single-version rules caught 10 of 28; code added
in the release showed the payload in 24, 12 of them missed by the single-version rules.

Only signals that ordinary releases almost never add are used (378 updates of 63 popular packages: see the log):
  import_time      a dangerous call that runs when the module is imported (module level, also inside a top-level
                   if/try/with/for; not inside a function) and was not there before: subprocess/os.system/socket/
                   urlopen/requests/ctypes/marshal/exec/eval of a non-constant ...
  binary_py        a .py file that is really a binary (num2words 0.5.15 shipped a Windows executable as _build.py)
  new_pth          a new .pth file with an import line (runs at every interpreter start: elementary-data, gpsea, ...)
  encoded_payload  a long encoded string added together with code that decodes, writes or runs something
A signal that the previous release already had is followed back with a binary search over older releases: if it first
appeared only days ago, the previous release was probably part of the same attack (litellm 1.82.7 -> 1.82.8, telnyx
4.87.1 -> 4.87.2, ...). Only REVIEW is raised; nothing is executed.

Every pattern and number of these signals is in guard/rules/post.json ("version_diff", "late_file"). The ML
features at the end of this file are the ML model's and stay here: changing them means retraining.
"""
from __future__ import annotations

import ast
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import rule_engine

RULES = rule_engine.current()
_VD = RULES.vd
LATE_FILE_DAYS = RULES.late_min_days          # the file pip installs came this many days or more after its release's first file...
LATE_FILE_RECENT_DAYS = RULES.late_within_days  # ...and was uploaded within this many days
RECENT_DAYS = int(_VD["recent_days"])         # a signal that first appeared within this many days counts as part of a fresh attack
MAX_BISECT_STEPS = int(_VD["max_bisect_steps"])  # 2^8 releases; a project with more is searched over its most recent 256
MAX_FILE_BYTES = int(_VD["max_file_bytes"])
MAX_SIGNALS = int(_VD["max_signals"])

_DANGER_PREFIX = RULES.vd_danger_prefixes
# builtins.__import__ is left out: vendored compatibility code calls it at import time (setuptools, wheel, scipy:
# 3 of the 4 hits on ordinary updates); none of the compromised releases needed it.
_BLOB = RULES.vd_blob
_BLOB_WITH = RULES.vd_blob_with
_SKIP = RULES.vd_skip
_BINARY = _VD["binary_py"]
_PTH = _VD["new_pth"]


# ------------------------------------------------------------------------------------------------ reading a release
def code_of(files: list[Path]) -> dict[str, list[str]]:
    """{path below the package root: lines} for .py and .pth files (what runs), tests and docs left out."""
    out = {}
    for p in files:
        try:
            if not p.is_file() or p.suffix not in (".py", ".pth") or p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        rel = str(p).replace("\\", "/").split(".unpacked/", 1)[-1]
        rel = re.sub(r"^[^/]+-\d[^/]*/", "", rel)          # name-1.2.3/ of an sdist
        rel = re.sub(r"^src/", "", rel)
        if ".py/" in rel:
            rel = rel.split(".py/")[-1]
        if _SKIP.search(rel):
            continue
        out[rel] = p.read_text(errors="replace").splitlines()
    return out


def _dotted(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


_QUICK = RULES.vd_quick
_QUICK_ADDED = RULES.vd_quick_added


def import_time_calls(src: str) -> set[str] | None:
    """Dangerous calls run when the module is imported, as resolved names ('subprocess.Popen'). None: not Python.
    One pass over everything outside function bodies (imports there set the aliases; calls there run at import)."""
    if not _QUICK.search(src):
        return set()                                       # no dangerous name at all: skip the parse (big projects)
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    alias = dict(RULES.vd_builtin_names)
    calls = []
    stack = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue                                       # runs only when called
        if isinstance(node, ast.Import):
            for a in node.names:
                alias[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.module:
            for a in node.names:
                alias[a.asname or a.name] = f"{node.module}.{a.name}"
        elif isinstance(node, ast.Call):
            calls.append(node)
        stack.extend(ast.iter_child_nodes(node))
    found: set[str] = set()
    for node in calls:
        d = _dotted(node.func)
        if not d:
            continue
        root, _, rest = d.partition(".")
        full = alias.get(root, root) + ("." + rest if rest else "")
        constant = node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
        if full.startswith(_DANGER_PREFIX) and not (full.startswith(RULES.vd_constant_ok) and constant):
            found.add(full)                                # exec("from x import *") of a fixed string is not a payload
    return found


def _binary(lines: list[str]) -> bool:
    s = "\n".join(lines[:int(_BINARY["head_lines"])])
    return (any(c in s for c in _BINARY["contains"]) or s.startswith(tuple(_BINARY["starts_with"]))
            or s.count("\ufffd") > int(_BINARY["max_replacement_chars"]))


def _match(old: dict, key: str):
    if key in old:
        return old[key]
    tail = key.rsplit("/", 1)[-1]
    for k in old:
        if k.rsplit("/", 1)[-1] == tail and (k.endswith(key.split("/", 1)[-1]) or key.endswith(k.split("/", 1)[-1])):
            return old[k]
    return None


def signals(new: dict, old: dict | None) -> list[dict]:
    """Narrow signals in `new` that `old` (the release before, None = compare with nothing) did not have."""
    old = old or {}
    hits = []
    for key, lines in new.items():
        base = _match(old, key)
        if base == lines:
            continue
        if key.endswith(".pth"):
            imp = _PTH["line_prefix"]
            if base is None and any(l.lstrip().startswith(imp) for l in lines):
                hits.append({"kind": "new_pth", "file": key,
                             "detail": next(l.strip() for l in lines if l.lstrip().startswith(imp))[:int(_PTH["detail_max"])]})
            continue
        if _binary(lines):
            if base is None or not _binary(base):
                hits.append({"kind": "binary_py", "file": key, "detail": _BINARY["detail"]})
            continue
        if base is None:
            added = lines
        else:
            seen = set(base)
            added = [l for l in lines if l not in seen]    # lines this release added (order kept; cheaper than difflib)
        joined = "\n".join(added)
        # a new dangerous call needs its name on an added line; files whose added lines name none are not parsed
        # (transformers 5.17 -> 5.20 changes hundreds of files: parsing them all took 30 s)
        if _QUICK_ADDED.search(joined):
            now = import_time_calls("\n".join(lines))
            before = import_time_calls("\n".join(base)) if base is not None else set()
            if now and before is not None:
                for call in sorted(now - before):
                    hits.append({"kind": "import_time", "file": key, "detail": call})
        if _BLOB.search(joined) and _BLOB_WITH.search(joined):
            hits.append({"kind": "encoded_payload", "file": key, "detail": _VD["encoded_payload"]["detail"]})
    return hits


def _sig_key(h: dict) -> tuple:
    return (h["kind"], h["file"].rsplit("/", 1)[-1], h["detail"] if h["kind"] == "import_time" else "")


# ------------------------------------------------------------------------------------------------ release history
def _vkey(v: str):
    try:
        from _vendor.packaging.version import Version
        return (0, Version(v))
    except Exception:
        return (1, tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-+]", v)))


def history(meta: dict, upto: str) -> list[tuple[str, datetime]]:
    """Releases before `upto` in version order (files present, not yanked), with their first upload time.
    Pre-releases are left out unless `upto` is one."""
    def pre(v):
        return bool(RULES.vd_prerelease.search(v))
    out = []
    for v, files in (meta.get("releases") or {}).items():
        files = [x for x in files if not x.get("yanked")]
        if not files or v == upto or (pre(v) and not pre(upto)):
            continue
        try:
            if _vkey(v) >= _vkey(upto):
                continue
            t = min(datetime.fromisoformat(x["upload_time_iso_8601"].replace("Z", "+00:00")) for x in files)
        except Exception:
            continue
        out.append((v, t))
    return sorted(out, key=lambda x: _vkey(x[0]))


def fetch_code(name: str, version: str, meta: dict) -> dict | None:
    from sources import pypi
    with tempfile.TemporaryDirectory() as t:
        try:
            _, files = pypi.fetch(name, version, Path(t), {}, meta)
        except Exception:
            return None
        return code_of(files) if files else None


# ------------------------------------------------------------------------------------------------ ML features
_API = {
    "subprocess": r"subprocess\.|Popen\(", "os_exec": r"os\.(system|popen|exec\w*|spawn\w*)\(", "socket": r"\bsocket\.",
    "http": r"urlopen\(|urlretrieve\(|requests\.(get|post)\(|httpx\.(get|post)\(|http\.client", "eval_exec": r"(?<![\w.])(eval|exec|compile)\(",
    "decode": r"b64decode\(|marshal\.loads\(|zlib\.decompress\(|codecs\.decode\(", "ctypes": r"\bctypes\.",
    "env_secrets": r"os\.environ|getenv\(|\.ssh|\.aws|\.npmrc|\.pypirc", "file_write": r"open\([^)]*['\"][wa]b?['\"]",
    "tmp": r"/tmp/|tempfile\.", "chmod": r"os\.chmod\(|chmod ",
}
_API_RE = {k: re.compile(v) for k, v in _API.items()}


def _entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def features(new: dict, prev: dict, days_between: float | None = None) -> dict:
    """Numbers describing what this release added, for the ML model (not used by the guard's verdict).
    The broad signals here also occur in ordinary updates, which is why they are features and not rules."""
    changed = new_files = added_lines = 0
    added_api = {k: 0 for k in _API}
    prev_api = {k: False for k in _API}
    max_ent = 0.0
    for lines in prev.values():
        text = "\n".join(lines)
        for k, rx in _API_RE.items():
            if not prev_api[k] and rx.search(text):
                prev_api[k] = True
    for key, lines in new.items():
        base = _match(prev, key)
        if base == lines:
            continue
        if base is None:
            new_files += 1
            added = lines
        else:
            changed += 1
            seen = set(base)
            added = [l for l in lines if l not in seen]
        added_lines += len(added)
        for l in added:
            s = l.strip()
            if not s or s.startswith("#"):
                continue
            for k, rx in _API_RE.items():
                if rx.search(s):
                    added_api[k] += 1
            if len(s) >= 80:
                max_ent = max(max_ent, _entropy(s))
    narrow = signals(new, prev)
    total_files = max(1, len(new))
    return {
        "vd_files_changed": changed, "vd_files_new": new_files, "vd_files_changed_ratio": round((changed + new_files) / total_files, 4),
        "vd_lines_added": added_lines,
        **{f"vd_added_{k}": v for k, v in added_api.items()},
        "vd_new_api_kinds": sum(1 for k in _API if added_api[k] and not prev_api[k]),
        "vd_added_max_line_entropy": round(max_ent, 3),
        "vd_narrow_import_time": sum(1 for h in narrow if h["kind"] == "import_time"),
        "vd_narrow_binary_py": sum(1 for h in narrow if h["kind"] == "binary_py"),
        "vd_narrow_new_pth": sum(1 for h in narrow if h["kind"] == "new_pth"),
        "vd_narrow_encoded_payload": sum(1 for h in narrow if h["kind"] == "encoded_payload"),
        "vd_days_since_previous": round(days_between, 2) if days_between is not None else None,
    }


def check(name: str, version: str | None, meta: dict | None = None, fetch=fetch_code, now: datetime | None = None,
          features_out: dict | None = None) -> dict | None:
    """{"previous", "signals", "since", "safe_version"} when this release adds a narrow signal, else None.
    None (no opinion) as well when there is no earlier release or anything cannot be read.

    Only differences are analysed (the changed files), never a whole release on its own: litellm has 2,684 files and
    reading all of them took 23 s, the diff with the previous release 1.9 s (measured 2026-10-15).
    Downloads: 2 (this release and the previous one, in parallel). When nothing is new but the previous release came out
    within RECENT_DAYS, 1 more: the newest release from before that window. Whatever this release has that one did not
    appeared inside the window - possibly one attack over several releases (litellm 1.82.7 -> 1.82.8) - and a binary
    search inside the window finds the first release that had it."""
    from concurrent.futures import ThreadPoolExecutor
    from sources import pypi
    meta = meta or pypi.metadata(name)
    version = version or (meta.get("info") or {}).get("version")
    if not version:
        return None
    hist = history(meta, version)
    if not hist:
        return None                                        # first release: the new-package rule covers it
    prev_v, prev_t = hist[-1]
    with ThreadPoolExecutor(2) as pool:
        new_f, prev_f = pool.submit(fetch, name, version, meta), pool.submit(fetch, name, prev_v, meta)
        new, prev = new_f.result(), prev_f.result()
    if not new or prev is None:
        return None
    added = signals(new, prev)
    if features_out is not None:                           # for the ML model (recorded, not part of the verdict)
        try:
            cur_t = min(datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
                        for f in (meta.get("releases") or {}).get(version) or [])
            gap = (cur_t - prev_t).total_seconds() / 86400
        except Exception:
            gap = None
        features_out.update(features(new, prev, gap), vd_previous=prev_v)
    if added:
        return {"previous": prev_v, "signals": added[:MAX_SIGNALS], "since": None, "safe_version": prev_v}
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=RECENT_DAYS)
    if prev_t < cutoff:
        return None                                        # anything risky here was already there over RECENT_DAYS ago
    window = [(v, t) for v, t in hist if t >= cutoff]
    before = [(v, t) for v, t in hist if t < cutoff]
    if not before:
        return None                                        # the whole project is younger than the window (new-package rule)
    base = fetch(name, before[-1][0], meta)
    if base is None:
        return None
    recent = signals(new, base)
    if not recent:
        return None                                        # already there before the window: normal for this project
    target = {_sig_key(h) for h in recent}

    def has(v):
        code = fetch(name, v, meta)
        return code is not None and bool(target & {_sig_key(h) for h in signals(code, base)})

    lo, hi = 0, len(window) - 1                            # window[hi] (= previous) has it, base does not
    for _ in range(MAX_BISECT_STEPS):
        if lo >= hi:
            break
        mid = (lo + hi) // 2
        if has(window[mid][0]):
            hi = mid
        else:
            lo = mid + 1
    first_v, first_t = window[lo]
    safe = window[lo - 1][0] if lo > 0 else before[-1][0]
    return {"previous": prev_v, "signals": recent[:MAX_SIGNALS], "since": {"version": first_v, "days": (now - first_t).days},
            "safe_version": safe}


# ------------------------------------------------------------------------------------------------ files added later
def late_file(meta: dict, version: str | None, now: datetime | None = None) -> dict | None:
    """The file pip would install for `version` was ADDED to that release long after it came out, and recently.
    PyPI never lets an uploaded file be replaced, but it does let a new file be added to an old release (a wheel where
    there was only an sdist, a wheel for another platform); pip prefers it, so `foo==1.2.0` users would get it.
    Ordinary projects (1,300 popular ones, 109,190 releases, measured 2026-10-16): the chosen file was >= 7 days
    late in 155 releases, all of them backfills from long ago; >= 7 days late AND uploaded in the last 90 days: 0."""
    import artifact_select
    version = version or (meta.get("info") or {}).get("version")
    files = [f for f in ((meta.get("releases") or {}).get(version) or []) if not f.get("yanked")]
    if len(files) < 2:
        return None

    def t(f):
        return datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
    try:
        chosen, _kind, _ = artifact_select.choose(files)
        if not chosen:
            return None
        first, added = min(t(f) for f in files), t(chosen)
    except Exception:
        return None
    now = now or datetime.now(timezone.utc)
    late, ago = (added - first).days, (now - added).days
    if late < LATE_FILE_DAYS or ago > LATE_FILE_RECENT_DAYS:
        return None
    hist = history(meta, version)
    return {"file": os.path.basename(str(chosen.get("filename", ""))), "release_date": first.date().isoformat(),
            "added_days_after": late, "added_days_ago": ago, "safe_version": hist[-1][0] if hist else None}
