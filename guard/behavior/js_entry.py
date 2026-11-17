"""Which JavaScript files of an npm package run when the package is loaded.

`require("pkg")` / `import "pkg"` runs the entry files package.json declares (main, module, browser, exports) and the
files they load with a literal relative require / import, transitively. Other files (browser builds, CDN bundles, files
only a deep `require("pkg/dist/x.js")` reaches) run only when someone asks for them by path. `bin` files run as commands.

When a loaded file asks for a module by a computed name (`require(name)`, `import(x)`) the files it can reach are not
known; then every file is taken to run on load, as before (None).
"""
from __future__ import annotations

import json
import posixpath
import re
from pathlib import Path

_EXTS = (".js", ".cjs", ".mjs", ".jsx")
_SPEC = r"""(?:'([^'\n]*)'|"([^"\n]*)"|`([^`$\n]*)`)"""
_STATIC = re.compile(r"""(?:\brequire\s*\(\s*|\bimport\s*\(\s*|\bfrom\s*|\bimport\s+|\bexport\s*\*\s*from\s*)""" + _SPEC)
_CALL = re.compile(r"""(?<![\w$.])(?:require|import)\s*\(\s*([^\s)])""")
# require used as a value or through another name loads modules this cannot follow: `const r = require; r(x)`,
# `factory(require)`, `module.require(x)`, `createRequire(url)(x)`, `globalThis["require"]`
_ALIAS = re.compile(r"""(?:[=:(,?]|\breturn)\s*require\s*(?:[;,)}\n]|$)|\bmodule\s*\.\s*require\s*\(\s*[^'"`\s)]"""
                    r"""|\bcreateRequire\s*\(|\[\s*['"`]require['"`]\s*\]""", re.M)
_READ_LIMIT = 8 * 1024 * 1024
# a file of the package named as a string: what spawn("node", [f]), fork(f), new Worker(f) or a path built from
# __dirname runs. Any such string in loaded code counts as loaded too (a file named and not run costs one more read)
_FILE_LITERAL = re.compile(r"""['"`]((?:\.{0,2}/)?[\w@.\-/]+\.(?:c|m)?js)['"`]""")
_DIRNAME_JOIN = re.compile(r"""\.(?:join|resolve)\(\s*__dirname\s*((?:,\s*['"`][^'"`\n]+['"`]\s*)+)\)""")


def _strings(node, out: list[str]) -> None:
    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for v in node.values():
            _strings(v, out)
    elif isinstance(node, list):
        for v in node:
            _strings(v, out)


def _entry_specs(pkg: dict) -> tuple[list[str], list[str]]:
    """(files loading the package runs, bin files) as written in package.json. Subpath patterns ("./x/*") are left out:
    those files load only when asked for by path."""
    load: list[str] = []
    main = pkg.get("main")
    load.append(main if isinstance(main, str) and main.strip() else "index.js")
    for key in ("module", "browser"):
        v = pkg.get(key)
        if isinstance(v, str):
            load.append(v)
        elif isinstance(v, dict) and key == "browser":
            load += [x for x in v.values() if isinstance(x, str)]
    exp = pkg.get("exports")
    if exp is not None:
        if isinstance(exp, dict) and any(isinstance(k, str) and k.startswith(".") for k in exp):
            for k, v in exp.items():
                if isinstance(k, str) and "*" not in k:
                    _strings(v, load)
        else:
            _strings(exp, load)
    load = [x for x in load if "*" not in x]
    bins: list[str] = []
    b = pkg.get("bin")
    if isinstance(b, str):
        bins.append(b)
    elif isinstance(b, dict):
        bins += [x for x in b.values() if isinstance(x, str)]
    return load, bins


def _resolve(spec: str, base_dir: str, files: dict[str, Path], depth: int = 0) -> str | None:
    p = posixpath.normpath(posixpath.join(base_dir, spec)).lstrip("/")
    if p.startswith(".."):
        return None
    for cand in (p, *(p + e for e in _EXTS)):
        if cand in files:
            return cand
    nested = files.get(posixpath.join(p, "package.json"))    # a folder: its package.json main first, then index
    if nested is not None and depth < 8:
        try:
            main = json.loads(nested.read_text(errors="replace")).get("main")
        except (OSError, ValueError):
            main = None
        if isinstance(main, str) and main.strip():
            hit = _resolve(main, p, files, depth + 1)
            if hit:
                return hit
    for cand in (posixpath.join(p, "index" + e) for e in _EXTS):
        if cand in files:
            return cand
    return None


def _requests(text: str) -> tuple[list[str], bool]:
    """(literal module names the text loads, whether it also loads one by a computed name)."""
    specs = [a or b or c for a, b, c in _STATIC.findall(text)]
    dynamic = any(m.group(1) not in "'\"`" for m in _CALL.finditer(text)) or bool(_ALIAS.search(text))
    return specs, dynamic


def loaded_files(files: dict[str, Path], name: str | None = None) -> tuple[set[str], set[str]] | None:
    """({package-relative files that run on load}, {bin files}) or None when that cannot be told (no package.json, or a
    loaded file asks for a module by a computed name). `files` maps package-relative paths to the extracted files."""
    pj = files.get("package.json")
    if pj is None:
        return None
    try:
        pkg = json.loads(pj.read_text(errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(pkg, dict):
        return None
    name = name or (pkg.get("name") if isinstance(pkg.get("name"), str) else None)
    load_specs, bin_specs = _entry_specs(pkg)
    todo = [r for r in (_resolve(s, "", files) for s in load_specs) if r]
    seen: set[str] = set()
    while todo:
        rel = todo.pop()
        if rel in seen or not rel.endswith(_EXTS):
            continue
        seen.add(rel)
        try:
            if files[rel].stat().st_size > _READ_LIMIT:
                return None
            text = files[rel].read_text(errors="replace")
        except OSError:
            return None
        specs, dynamic = _requests(text)
        if dynamic:
            return None
        named = [m.group(1) for m in _FILE_LITERAL.finditer(text)]
        named += ["/".join(re.findall(r"""['"`]([^'"`]+)['"`]""", m.group(1))) for m in _DIRNAME_JOIN.finditer(text)]
        for lit in named:
            if "://" in lit:
                continue
            target = _resolve(lit if lit.startswith(".") else "./" + lit, posixpath.dirname(rel), files) \
                or _resolve(lit.lstrip("./"), "", files)
            if target and target not in seen:
                todo.append(target)
        for spec in specs:
            if spec.startswith("."):
                target = _resolve(spec, posixpath.dirname(rel), files)
            elif name and spec.startswith(name + "/"):
                target = _resolve("./" + spec[len(name) + 1:], "", files)
            else:
                continue                          # another package: scanned as a dependency of its own
            if target and target not in seen:
                todo.append(target)
    bins = {r for r in (_resolve(s, "", files) for s in bin_specs) if r}
    return seen, bins
