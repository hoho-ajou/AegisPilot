"""
AegisPilot - npm packages as a source: registry metadata, version ranges, the tarball.

What npm would install is read the way pip's is: the registry's metadata picks the version (an exact version, a
dist-tag such as `latest`, or a semver range like `^1.2.0`), the tarball is downloaded and unpacked with the same limits
as a wheel (safe_extract), and nothing in it is run. npm runs a package's own code at install through its lifecycle
scripts (package.json "preinstall", "install", "postinstall"); those commands are written next to the files as
`package.json#<event>.sh` so the shell rules read them like any other file.

Not here: dependencies of the package (npm installs the whole tree and runs their lifecycle scripts too - see
transitive_malicious for the lock-file check), registries other than registry.npmjs.org (reported as unscanned).
"""
from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from pathlib import Path

REGISTRY = "https://registry.npmjs.org"
TIMEOUT = 20
MAX_TARBALL_BYTES = 200 * 1024 * 1024
LIFECYCLE = ("preinstall", "install", "postinstall")        # run when the package is installed as a dependency
# file types kept from the tarball: JavaScript, package.json, scripts the lifecycle may call, and text an agent reads
KEEP_SUFFIXES = (".js", ".mjs", ".cjs", ".json", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".py", ".md")
_NAME = re.compile(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", re.I)


def valid_name(name: str) -> bool:
    return bool(_NAME.match(name or "")) and len(name) <= 214


def metadata(name: str) -> dict:
    """The registry's abbreviated document (versions, dist-tags, tarball URLs) - what npm itself reads to install."""
    url = f"{REGISTRY}/{urllib.parse.quote(name, safe='@')}"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.npm.install-v1+json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read())


# --------------------------------------------------------------------------------------------- semver (npm's subset)

_VER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def parse(v: str):
    """(major, minor, patch, prerelease) or None. A release sorts above its prereleases."""
    m = _VER.match(v.strip())
    if not m:
        return None
    pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split(".")) if m.group(4) else None
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), pre


def _key(p):
    pre = p[3]
    # numeric identifiers sort below alphanumeric ones (semver 11.4.4); no prerelease sorts above any prerelease
    return (p[0], p[1], p[2], 1, ()) if pre is None else \
        (p[0], p[1], p[2], 0, tuple((0, x, "") if isinstance(x, int) else (1, 0, x) for x in pre))


def _partial(v: str):
    """'1', '1.2', '1.x', '1.2.3-rc.1' -> (parts with None for a wildcard, prerelease)."""
    v = v.strip().lstrip("v=")
    if v in ("", "*", "x", "X"):
        return [None, None, None], None
    core, _, pre = v.partition("-")
    core = core.split("+")[0]
    bits = core.split(".")
    if len(bits) > 3 or not all(b.isdigit() or b in ("x", "X", "*") for b in bits):
        raise ValueError(v)
    parts = [int(b) if b.isdigit() else None for b in bits] + [None] * (3 - len(bits))
    for i in range(1, 3):                       # 1.x.3 -> 1.x.x
        if parts[i - 1] is None:
            parts[i] = None
    return parts, (pre or None)


def _bounds(op: str, v: str) -> list[tuple[str, tuple]]:
    """A comparator as a list of (operator, key) bounds."""
    parts, pre = _partial(v)
    M, m, p = parts
    lo = (M or 0, m or 0, p or 0)
    full = lambda a: parse(".".join(map(str, a)) + (f"-{pre}" if pre and None not in parts else ""))  # noqa: E731
    floor = lambda a: _key((*a, (0,)))          # the lowest prerelease: "<2.0.0-0"  # noqa: E731
    if M is None:
        return [] if op in ("", "=", ">=", "<=") else [("<", floor((0, 0, 0)))] if op == "<" else []
    if op == "^":
        if M > 0 or m is None:
            hi = (M + 1, 0, 0)
        elif m > 0 or p is None:
            hi = (0, m + 1, 0)
        else:
            hi = (0, 0, p + 1)
        return [(">=", _key(full(lo))), ("<", floor(hi))]
    if op == "~":
        hi = (M + 1, 0, 0) if m is None else (M, m + 1, 0)
        return [(">=", _key(full(lo))), ("<", floor(hi))]
    if None in parts:                           # 1.2 / 1.x with = or a comparison
        hi = (M + 1, 0, 0) if m is None else (M, m + 1, 0)
        return {"": [(">=", _key(full(lo))), ("<", floor(hi))], "=": [(">=", _key(full(lo))), ("<", floor(hi))],
                ">=": [(">=", _key(full(lo)))], "<": [("<", floor(lo))], ">": [(">=", floor(hi))],
                "<=": [("<", floor(hi))]}[op]
    k = _key(full(lo))
    return [("==", k)] if op in ("", "=") else [(op, k)]


def _range_sets(spec: str) -> list[tuple[list, bool]]:
    """`^1.2 || >=3 <4` -> [(bounds, allows_prerelease), ...]."""
    out = []
    for alt in spec.split("||"):
        alt = alt.strip()
        m = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alt)          # hyphen range: 1.2.3 - 2.3 means >=1.2.3 <2.4.0-0
        if m:
            hi = m.group(2)
            upper = [b for b in _bounds("", hi) if b[0] == "<"] if None in _partial(hi)[0] else _bounds("<=", hi)
            out.append((_bounds(">=", m.group(1)) + upper, "-" in alt.replace(" - ", " ")))
            continue
        bounds = []
        for tok in re.findall(r"(>=|<=|>|<|=|\^|~>?|)\s*([^\s<>=^~]+)", alt) if alt else [("", "*")]:
            op, v = tok
            bounds += _bounds("~" if op == "~>" else op, v)
        out.append((bounds, "-" in alt))           # a range naming a prerelease lets prereleases match (simplified)
    return out


def satisfies(version: str, spec: str) -> bool:
    p = parse(version)
    if p is None:
        return False
    k = _key(p)
    for bounds, allow_pre in _range_sets(spec):
        if p[3] is not None and not allow_pre:
            continue
        ok = True
        for op, b in bounds:
            if not {"==": k == b, ">=": k >= b, ">": k > b, "<": k < b, "<=": k <= b}[op]:
                ok = False
                break
        if ok:
            return True
    return False


def pick_version(meta: dict, spec: str | None) -> str | None:
    """The version npm installs for `spec`: a dist-tag (default `latest`), an exact version, else the highest that
    satisfies the range. None if nothing matches or the spec cannot be read."""
    tags = meta.get("dist-tags") or {}
    versions = list((meta.get("versions") or {}).keys())
    spec = (spec or "").strip()
    if spec in ("", "*", "latest") or spec in tags:
        tagged = tags.get(spec or "latest")
        if tagged in versions:
            return tagged
        if spec in ("", "*", "latest") and not tagged:
            spec = "*"
        elif spec not in ("", "*"):
            return None
    if spec in versions:
        return spec
    latest = tags.get("latest")
    try:
        if latest in versions and satisfies(latest, spec):      # npm prefers the `latest` tag when it fits the range
            return latest
        good = [v for v in versions if satisfies(v, spec)]
    except (ValueError, KeyError):
        return None
    return max(good, key=lambda v: _key(parse(v))) if good else None


# ----------------------------------------------------------------------------------------------------- the tarball

def lifecycle_scripts(package_json: Path) -> dict[str, str]:
    """{event: command} of the scripts npm runs when this package is installed."""
    try:
        doc = json.loads(package_json.read_text(errors="replace"))
    except (OSError, ValueError):
        return {}
    scripts = doc.get("scripts") if isinstance(doc, dict) else None
    if not isinstance(scripts, dict):
        return {}
    return {e: str(scripts[e]) for e in LIFECYCLE if isinstance(scripts.get(e), str) and scripts[e].strip()}


def write_lifecycle(files: list[Path], dest: Path, base_name: str) -> list[Path]:
    """The lifecycle commands of the package root's package.json as `package.json#<event>.sh` files (read by the shell
    rules; the evidence then points at the event). Returns the files written."""
    pkgs = [f for f in files if f.name == "package.json" and f.is_file()]
    if not pkgs:
        return []
    root_json = min(pkgs, key=lambda f: len(f.parts))
    scripts = lifecycle_scripts(root_json)
    if not scripts:
        return []
    out_dir = dest / f"{base_name}.scripts.unpacked"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for event, cmd in scripts.items():
        f = out_dir / f"package.json#{event}.sh"
        f.write_text(cmd + "\n")
        out.append(f)
        code = inline_node_code(cmd)
        if code:                            # `node -e "<code>"`: the JavaScript rules read the code itself
            js = out_dir / f"package.json#{event}.js"
            js.write_text(code + "\n")
            out.append(js)
    return out


def install_time_files(files: list[Path], events: tuple = LIFECYCLE) -> list[str]:
    """Package files the install scripts run (`node install.js`, `sh ./scripts/postinstall.sh`), relative to the package
    root: code in them runs at install, not when the package is used (attack_path.context_of)."""
    import shlex
    pkgs = [f for f in files if f.name == "package.json" and f.is_file()]
    if not pkgs:
        return []
    root_json = min(pkgs, key=lambda f: len(f.parts))
    try:
        scripts = (json.loads(root_json.read_text(errors="replace")).get("scripts") or {})
    except (OSError, ValueError, AttributeError):
        return []
    out = []
    for event in events:
        cmd = scripts.get(event) if isinstance(scripts, dict) else None
        try:
            toks = shlex.split(cmd) if isinstance(cmd, str) else []
        except ValueError:
            continue
        for t in toks:
            if re.search(r"\.(c|m)?js$|\.sh$|\.py$", t) and not t.startswith(("-", "/")) and ".." not in t:
                out.append(re.sub(r"^\./", "", t))
    return list(dict.fromkeys(out))


def inline_node_code(cmd: str) -> str | None:
    """The code of `node -e CODE` / `node --eval=CODE` / `node -p CODE` in a lifecycle command, else None."""
    import shlex
    try:
        toks = shlex.split(cmd)
    except ValueError:
        return None
    for i, t in enumerate(toks):
        if Path(t).name not in ("node", "nodejs"):
            continue
        for j in range(i + 1, len(toks)):
            a = toks[j]
            if a in ("-e", "--eval", "-p", "--print") and j + 1 < len(toks):
                return toks[j + 1]
            if a.startswith(("--eval=", "--print=")):
                return a.split("=", 1)[1]
            if not a.startswith("-"):
                break
    return None


def fetch(name: str, spec: str | None, dest: Path, meta: dict | None = None, info: dict | None = None) -> tuple[str | None, list[Path]]:
    """(resolved version, unpacked files + lifecycle files). Nothing is run. info gets artifact, scripts, integrity."""
    import safe_extract
    meta = meta or metadata(name)
    version = pick_version(meta, spec)
    if version is None:
        raise ValueError(f"no version on npm matches '{name}@{spec or 'latest'}'")
    dist = ((meta.get("versions") or {}).get(version) or {}).get("dist") or {}
    url = dist.get("tarball", "")
    if not url.startswith(REGISTRY + "/"):
        raise ValueError("tarball address in the npm metadata is not registry.npmjs.org")
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        raw = resp.read(MAX_TARBALL_BYTES + 1)
    if len(raw) > MAX_TARBALL_BYTES:
        raise ValueError(f"package too large, code not scanned (>{MAX_TARBALL_BYTES >> 20}MB limit)")
    base = f"{name.replace('/', '__')}-{version}"
    root = dest / f"{base}.tgz.unpacked"
    root.mkdir(parents=True, exist_ok=True)
    skipped: list = []
    safe_extract.extract_targz(raw, root, skipped, KEEP_SUFFIXES)
    files = list(root.rglob("*"))
    life = write_lifecycle(files, dest, base)
    if info is not None:
        info.update(artifact=url.rsplit("/", 1)[-1], artifact_kind="npm", skipped=skipped,
                    scripts={f.name.split("#", 1)[1][:-3]: f.read_text().strip()[:200] for f in life},
                    integrity=dist.get("integrity"))
    return version, files + life



# ------------------------------------------------------------------------------------------ the locked dependency tree

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_MAX = 1000


def malicious_releases(pairs: list[tuple[str, str]]) -> dict[tuple[str, str], list[str]]:
    """{(name, version): [MAL- ids]} for the releases OSV's malicious-packages records name. One batch request per
    1,000 releases; only the ids come back, which is enough (MAL- is the malicious-packages database)."""
    import rule_engine
    prefixes = rule_engine.current().malicious_id_prefixes
    pairs = list(dict.fromkeys(pairs))
    out: dict = {}
    for i in range(0, len(pairs), OSV_BATCH_MAX):
        chunk = pairs[i:i + OSV_BATCH_MAX]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]}).encode()
        req = urllib.request.Request(OSV_BATCH_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            results = json.loads(resp.read()).get("results", [])
        for (n, v), r in zip(chunk, results):
            ids = [x.get("id", "") for x in (r or {}).get("vulns", []) if str(x.get("id", "")).startswith(prefixes)]
            if ids:
                out[(n, v)] = ids
    return out


# ------------------------------------------------------------------------- dependencies that run code at install
# npm runs the preinstall / install / postinstall scripts of EVERY package in the tree, not only the ones named in the
# command - the usual way in for npm attacks (ua-parser-js 2021, the 2025 Shai-Hulud worm). Scanning every dependency's
# code would take minutes; scanning the ones that have an install script is what matters for "code runs at install".
# The registry's abbreviated document and package-lock.json both say which versions have one (hasInstallScript).

TREE_MAX_PACKAGES = 1000          # distinct packages per command: 198 popular packages measured at most 537 (nuxt, 4 s)
TREE_WORKERS = 8


def install_script_deps(roots: list[tuple[str, str | None]], deadline: float, skip: set | None = None) -> tuple[list[dict], list[str]]:
    """([{name, version, via}] of packages in the dependency tree of `roots` (name, spec) whose resolved version has an
    install script, [notes]). The tree is resolved like npm does for a fresh install (dependencies + optionalDependencies,
    highest version in range); `skip` = names already scanned. Stops at TREE_MAX_PACKAGES or `deadline` (noted)."""
    import time
    from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
    skip = set(skip or ())
    seen: set = set()                     # (name, range) pairs resolved: one package is asked for with many ranges
    names: set = set()                    # distinct packages - what the limit counts
    found: list[dict] = []
    notes: list[str] = []
    queue = [(n, s, None) for n, s in roots]
    meta_cache: dict = {}

    def resolve(name, spec):
        meta = meta_cache.get(name) or metadata(name)
        meta_cache[name] = meta
        version = pick_version(meta, spec)
        info = ((meta.get("versions") or {}).get(version) or {}) if version else {}
        return version, info

    with ThreadPoolExecutor(TREE_WORKERS) as pool:
        running: dict = {}
        while queue or running:
            while queue and len(running) < TREE_WORKERS * 2:
                name, spec, via = queue.pop(0)
                if (name, spec) in seen or not valid_name(name):
                    continue
                if name not in names and len(names) >= TREE_MAX_PACKAGES:
                    notes.append(f"many dependencies: only the first {TREE_MAX_PACKAGES} distinct packages checked")
                    queue.clear()
                    break
                seen.add((name, spec))
                names.add(name)
                running[pool.submit(resolve, name, spec)] = (name, via)
            if not running:
                break
            left = deadline - time.monotonic()
            if left <= 0:
                notes.append("dependency tree not fully checked within the time limit")
                break
            done, _ = wait(list(running), timeout=left, return_when=FIRST_COMPLETED)
            for fut in done:
                name, via = running.pop(fut)
                try:
                    version, info = fut.result()
                except Exception:
                    continue                      # an unreadable dependency: npm itself would fail on it
                if not version:
                    continue
                if info.get("hasInstallScript") and name not in skip:
                    found.append({"name": name, "version": version, "via": via})
                for key in ("dependencies", "optionalDependencies"):
                    for dep, dspec in (info.get(key) or {}).items() if isinstance(info.get(key), dict) else []:
                        if isinstance(dspec, str) and not dspec.startswith(("file:", "link:", "git", "http", "workspace:")):
                            queue.append((dep, dspec, via or name))
        for fut in running:
            fut.cancel()
    unique = {(f["name"], f["version"]): f for f in found}
    return list(unique.values()), list(dict.fromkeys(notes))


def lock_install_scripts(lock: dict) -> list[dict]:
    """[{name, version, via}] of package-lock.json (v2/v3) entries marked hasInstallScript."""
    out = []
    for path, info in (lock.get("packages") or {}).items():
        if not (path.startswith("node_modules/") and isinstance(info, dict) and info.get("hasInstallScript")
                and info.get("version") and not info.get("link")):
            continue
        parts = path.split("node_modules/")
        name = parts[-1].rstrip("/")
        via = parts[1].rstrip("/") if len(parts) > 2 else None
        out.append({"name": name, "version": str(info["version"]), "via": via})
    return out
