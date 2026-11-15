"""
AegisPilot ML - features of one npm package version, the npm counterpart of features.py.

    from npm_features import compute_from_archive, compute_from_dir
    r = compute_from_archive("x.zip", packument=doc, version="1.0.0", now=t)   # training: a tarball or a sample zip
    r = compute_from_dir(root, packument=doc, version="1.0.0")                 # the guard: the folder it unpacked
    r["raw"]                                                                   # feature name -> value

Why npm has its own features and its own model (see docs/ml-npm.md): the concepts are the PyPI model's (history of the
project, how it is packaged, what its code does at install), but the measurements are not the same quantities - the
code is another language, npm has no wheel or classifiers, and a minified one-line file is normal in npm and a strong
sign of hidden code in PyPI. One forest over both would learn each ecosystem's normal on its own anyway, and would put
the PyPI model's validated numbers at risk.

Three groups:
  REGISTRY_FEATURES  from the registry's full document (`time`, `versions`, `maintainers`), as it stood when the version
                     was checked: versions published up to this one, age of the package, maintainers. The malicious
                     training samples carry that document as it was when they were found (package_info-*.json).
  META_FEATURES      package.json, the file list and the lifecycle scripts of the tarball.
  JS_CODE_FEATURES   the JavaScript (js_code_features.py).
The model with REGISTRY_FEATURES is npm_full; npm_pkg leaves them out, for a version whose registry document could not
be read (too large, network failure).

- Only the files the guard keeps from a tarball (KEEP_SUFFIXES) are counted, so training samples (whole tarballs) and
  the guard's unpacked folder give the same numbers.
- The lifecycle scripts are parsed here the same way at training and at scan time (not by sources/npm.py, whose
  answers can change with the guard): which files `node`/`sh` run, `npm run` followed, `node -e` code.
- age_days is measured like PyPI's: whole days from the package's creation to the scan time (UTC), rounded down.
- Standard library only.
"""
import json
import posixpath
import re
import shlex

import js_code_features as JS
from js_code_features import JS_CODE_FEATURES

LIFECYCLE = ("preinstall", "install", "postinstall")
FREE_MAIL = {"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com",
             "qq.com", "163.com", "yandex.ru", "mail.ru"}
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
NET_CMD = re.compile(r"\b(?:curl|wget|nc|ncat|Invoke-WebRequest|iwr|certutil)\b|https?://", re.I)
_SPLIT = re.compile(r"&&|\|\||;|\|")

META_FEATURES = ["n_deps", "has_license", "has_home", "summary_len", "n_keywords", "author_empty", "email_count",
                 "free_email", "has_bin", "has_readme", "n_files", "total_size", "version_major", "has_gyp",
                 "has_install_script", "script_len", "script_network", "script_inline_node"]
REGISTRY_FEATURES = ["n_versions", "age_days", "n_maintainers", "maint_free_email"]
PKG_FEATURES = META_FEATURES + JS_CODE_FEATURES             # npm_pkg
NPM_FEATURES = REGISTRY_FEATURES + PKG_FEATURES             # npm_full
# Two stages, as for PyPI (ml/scan.py): an alert becomes REVIEW only with a code behavior signal - a SEVERE feature
# present, or another BEHAVIOR feature present that raised the score. A minified line is normal in npm, so line length
# is package profile here, not behavior.
SEVERE = ["decode_exec_chain", "auto_exec", "auto_process", "install_exec", "install_decode", "install_process",
          "install_network", "install_sensitive", "sensitive_cnt", "script_network", "script_inline_node"]
BEHAVIOR = SEVERE + ["auto_network", "obfuscation_rate", "exec_cnt", "decode_cnt", "long_blob_cnt", "obf_ident_cnt",
                     "process_cnt", "network_cnt", "recon_cnt", "has_install_script"]
LOG_FEATURES = ["n_versions", "age_days", "n_deps", "summary_len", "n_keywords", "n_files", "total_size",
                "version_major", "script_len", "n_js", "code_lines", "max_line_len", "obfuscation_rate", "exec_cnt",
                "decode_cnt", "long_blob_cnt", "obf_ident_cnt", "process_cnt", "network_cnt", "sensitive_cnt",
                "recon_cnt", "auto_process", "auto_network", "auto_exec", "decode_exec_chain"]


class NoPackageJson(Exception):
    """No readable package.json: not an npm package the model can read."""


# ------------------------------------------------------------------------------------------------ package.json

def _people(doc):
    out = []
    for key in ("author", "contributors", "maintainers"):
        v = doc.get(key)
        for p in (v if isinstance(v, list) else [v]):
            if isinstance(p, str):
                out.append(p)
            elif isinstance(p, dict):
                out.append(f"{p.get('name') or ''} <{p.get('email') or ''}> {p.get('url') or ''}")
    return out


def _author_name(doc):
    a = doc.get("author")
    if isinstance(a, dict):
        return str(a.get("name") or "").strip()
    if isinstance(a, str):
        return EMAIL_RE.sub("", re.sub(r"\(.*?\)|<.*?>", "", a)).strip()
    return ""


def _major(version):
    m = re.match(r"\s*v?(\d+)", str(version or ""))
    return min(int(m.group(1)), 100000) if m else 0


def meta_features(doc, paths, sizes):
    """Features of package.json and the file list (paths relative to the package root, sizes in bytes)."""
    emails = {e.lower() for e in EMAIL_RE.findall(" ".join(_people(doc)))}
    deps = doc.get("dependencies") if isinstance(doc.get("dependencies"), dict) else {}
    opt = doc.get("optionalDependencies") if isinstance(doc.get("optionalDependencies"), dict) else {}
    kw = doc.get("keywords")
    lic = doc.get("license") or doc.get("licenses")
    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    life = [str(scripts[e]) for e in LIFECYCLE if isinstance(scripts.get(e), str) and scripts[e].strip()]
    return {
        "n_deps": len(set(deps) | set(opt)),
        "has_license": int(bool(lic) and str(lic).strip().upper() not in ("", "UNLICENSED", "NONE")),
        "has_home": int(any(doc.get(k) for k in ("homepage", "repository", "bugs"))),
        "summary_len": len(str(doc.get("description") or "")),
        "n_keywords": len(kw) if isinstance(kw, list) else 0,
        "author_empty": int(_author_name(doc) == "" and not emails),
        "email_count": len(emails),
        "free_email": int(any(e.split("@")[1] in FREE_MAIL for e in emails)),
        "has_bin": int(bool(doc.get("bin"))),
        "has_readme": int(any(posixpath.dirname(p) == "" and p.lower().startswith("readme") for p in paths)),
        "n_files": len(paths),
        "total_size": sum(sizes),
        "version_major": _major(doc.get("version")),
        "has_gyp": int("binding.gyp" in paths),
        "has_install_script": int(bool(life)),
        "script_len": sum(len(s) for s in life),
        "script_network": int(any(NET_CMD.search(s) for s in life)),
        "script_inline_node": 0,                      # set by install_targets
    }


# ------------------------------------------------------------------------------------------ what the scripts run

def _node_file(spec, paths):
    spec = posixpath.normpath(spec.lstrip("./") if spec.startswith("./") else spec)
    if spec.startswith("..") or spec.startswith("/"):
        return None
    for cand in (spec, spec + ".js", spec + ".cjs", spec + ".mjs", posixpath.join(spec, "index.js")):
        if cand in paths:
            return cand
    return None


def install_targets(doc, paths, texts):
    """(files the lifecycle scripts run, `node -e` code, shell files they run, number of inline node programs)."""
    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    files, inline, shells = [], [], []
    todo = [str(scripts[e]) for e in LIFECYCLE if isinstance(scripts.get(e), str)]
    seen = 0
    while todo and seen < 20:
        cmd = todo.pop(0)
        seen += 1
        for part in _SPLIT.split(cmd):
            try:
                toks = shlex.split(part)
            except ValueError:
                toks = part.split()
            while toks and re.match(r"^\w+=", toks[0]):          # FOO=1 node x.js
                toks = toks[1:]
            if not toks:
                continue
            exe = posixpath.basename(toks[0])
            if exe in ("node", "nodejs"):
                rest = toks[1:]
                for j, a in enumerate(rest):
                    if a in ("-e", "--eval", "-p", "--print") and j + 1 < len(rest):
                        inline.append(rest[j + 1])
                        break
                    if a.startswith(("--eval=", "--print=")):
                        inline.append(a.split("=", 1)[1])
                        break
                    if not a.startswith("-"):
                        f = _node_file(a, paths)
                        if f:
                            files.append(f)
                        break
            elif exe in ("sh", "bash") and len(toks) > 1:
                f = _node_file(toks[1], paths)
                if f:
                    shells.append(f)
            elif exe in ("npm", "yarn", "pnpm") and len(toks) > 2 and toks[1] in ("run", "run-script"):
                s = scripts.get(toks[2])
                if isinstance(s, str):
                    todo.append(s)
            else:
                f = _node_file(toks[0], paths)               # ./install.js with a shebang
                if f and f.lower().endswith(JS.JS_SUFFIXES):
                    files.append(f)
                elif f:
                    shells.append(f)
    return list(dict.fromkeys(files)), inline, list(dict.fromkeys(shells))


# ------------------------------------------------------------------------------------------------- features

def compute(entries, packument=None, version=None, now=None):
    """entries = [(path, bytes)] of one package (any prefix): the raw features. NoPackageJson without a package.json.
    packument = the registry's full document (adds REGISTRY_FEATURES; registry_ok says whether they are there),
    version = the version checked (default: package.json's), now = the scan time (default: the current time)."""
    entries = list(entries)
    root = JS.package_root([p for p, _ in entries])
    files = {}
    for p, data in entries:
        rel = JS.norm(p, root)
        if rel.startswith(".."):
            continue
        files[rel] = data
    if "package.json" not in files:
        raise NoPackageJson("no package.json")
    try:
        doc = json.loads(files["package.json"].decode("utf-8-sig", "ignore"))
        if not isinstance(doc, dict):
            raise ValueError("not an object")
    except ValueError as e:
        raise NoPackageJson(f"package.json unreadable: {e}")
    paths = sorted(files)
    texts = {p: files[p].decode("utf-8", "ignore") for p in paths if p.lower().endswith(JS.JS_SUFFIXES)}
    raw = meta_features(doc, paths, [len(files[p]) for p in paths])
    run_files, inline, shells = install_targets(doc, set(paths), texts)
    raw["script_inline_node"] = len(inline)
    shell_text = " ".join(files[s].decode("utf-8", "ignore") for s in shells)
    raw["script_network"] = max(raw["script_network"], int(bool(NET_CMD.search(shell_text))))
    raw.update(JS.code_features(sorted(texts.items()), run_files, inline))
    name = str(doc.get("name") or "")
    version = version or str(doc.get("version") or "")
    registry_ok = False
    if isinstance(packument, dict):
        raw.update(registry_features(packument, version, now))
        registry_ok = True
    return {"raw": raw, "name": name, "version": version, "install_files": run_files, "registry_ok": registry_ok}


def compute_from_archive(path, packument=None, version=None, now=None):
    with open(path, "rb") as fh:
        data = fh.read()
    return compute(JS.iter_archive(data), packument, version, now)


def compute_from_dir(root, packument=None, version=None, now=None):
    return compute(JS.iter_dir(root), packument, version, now)


def _ts(s):
    import datetime
    t = datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def registry_features(packument, version, now=None):
    """REGISTRY_FEATURES from the registry's full document: versions published up to `version` (by `time`, unpublished
    ones included, as the registry lists them), whole days since the package was created, its maintainers."""
    import datetime
    t = packument.get("time") if isinstance(packument.get("time"), dict) else {}
    stamps = {}
    for k, v in t.items():
        if k in ("created", "modified") or not isinstance(v, str):
            continue
        try:
            stamps[k] = _ts(v)
        except ValueError:
            continue
    target = stamps.get(version)
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=datetime.timezone.utc)
    try:
        created = _ts(t["created"])
    except (KeyError, ValueError):
        created = min(stamps.values()) if stamps else now
    maint = packument.get("maintainers") if isinstance(packument.get("maintainers"), list) else []
    emails = {str(m.get("email") or "").lower() for m in maint if isinstance(m, dict)}
    emails |= {e.lower() for m in maint if isinstance(m, str) for e in EMAIL_RE.findall(m)}
    return {
        "n_versions": len([s for s in stamps.values() if target is None or s <= target]) or 1,
        "age_days": float(max(0, int((now - created).total_seconds() // 86400))),
        "n_maintainers": len(maint),
        "maint_free_email": int(any("@" in e and e.split("@")[1] in FREE_MAIL for e in emails)),
    }


def found_at(sample_path):
    """The day a DataDog sample was found, from its file name (`2025-11-24-name-v1.0.0.zip`), UTC midnight."""
    import datetime
    m = re.search(r"(?:^|/)(\d{4})-(\d{2})-(\d{2})-[^/]*$", sample_path)
    if not m:
        raise ValueError(f"no date in {sample_path}")
    return datetime.datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=datetime.timezone.utc)


def sample_packument(data):
    """The registry document a DataDog sample zip carries (package_info-*.json), or None."""
    import io
    import zipfile
    z = zipfile.ZipFile(io.BytesIO(data))
    z.setpassword(b"infected")
    for info in z.infolist():
        if re.search(r"(?:^|/)package_info-[^/]*\.json$", info.filename) and info.file_size <= 64 << 20:
            try:
                d = json.loads(z.read(info).decode("utf-8-sig", "ignore"))
            except ValueError:
                return None
            return d if isinstance(d, dict) else None
    return None
