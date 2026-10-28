"""
AegisPilot - which release file to analyze: the one pip will actually install.

Why: pip installs a compatible wheel when one exists and builds the sdist only when it does not. The first scanner
read the sdist whenever there was one, so it looked at a file that is usually NOT what gets installed (measured:
187 of 201 popular packages publish both). Consequences: (a) the sdist's `setup.py` signals (install hook, network
call in setup.py) were applied to installs where `setup.py` never runs - false REVIEWs (dumb-init, kaldialign,
grpcio, pillow, setuptools); (b) a payload that lives only in the wheel was never read, nor were wheel-only files
such as `.pth`.

Policy "installed" (default): compatible wheel (most specific tag first) > sdist > smallest wheel (nothing
compatible and no sdist: pip would fail, analyze something rather than nothing).
Policy "sdist_first": the previous behaviour, kept as an escape hatch / for before-after measurement.

"Compatible" means compatible with the interpreter running this guard, which is normally - but not always - the
interpreter pip will use (a project venv may differ). When the tag library is unavailable a conservative
heuristic is used. Either way, a wrong guess only changes WHICH real artifact of the release is read.
"""
from __future__ import annotations

import importlib
import itertools
import platform
import sys

POLICY_INSTALLED = "installed"
POLICY_SDIST_FIRST = "sdist_first"

_ARCH_ALIASES = {"x86_64": ("x86_64", "amd64"), "amd64": ("x86_64", "amd64"), "aarch64": ("aarch64", "arm64"),
                 "arm64": ("aarch64", "arm64")}


def _tag_library():
    for mod in ("packaging.tags", "pip._vendor.packaging.tags"):
        try:
            return importlib.import_module(mod)
        except Exception:
            continue
    return None


def wheel_tag_combos(filename: str) -> list[tuple[str, str, str]]:
    """(python, abi, platform) combinations a wheel filename declares (compressed tag sets expanded)."""
    parts = filename[:-4].split("-") if filename.endswith(".whl") else []
    if len(parts) < 5:
        return []
    return list(itertools.product(parts[-3].split("."), parts[-2].split("."), parts[-1].split(".")))


_TAG_ORDER: dict = {}


def _rank_with_library(lib, filename: str) -> int | None:
    """Position of the best matching tag in this interpreter's preference order (0 = most specific), else None."""
    # sys_tags() lists ~1,000 tags; building it once per wheel made a numpy release (~50 wheels) cost ~0.25 s
    # (measured 2026-10-16). The interpreter does not change during a run, so it is built once.
    order = _TAG_ORDER.get(id(lib))
    if order is None:
        order = _TAG_ORDER[id(lib)] = {str(t): i for i, t in enumerate(lib.sys_tags())}
    ranks = [order[f"{py}-{abi}-{plat}"] for py, abi, plat in wheel_tag_combos(filename) if f"{py}-{abi}-{plat}" in order]
    return min(ranks) if ranks else None


def _rank_heuristic(filename: str) -> int | None:
    """No tag library: accept pure-Python wheels, wheels built for this CPython, abi3 wheels for this or an older
    minor, on a matching OS/arch. Lower rank = more specific."""
    major, minor = sys.version_info[:2]
    arch = _ARCH_ALIASES.get(platform.machine().lower(), (platform.machine().lower(),))
    best = None
    for py, abi, plat in wheel_tag_combos(filename):
        rank = None
        if plat == "any":
            if py in ("py3", f"py{major}", f"py{major}{minor}") or (py.startswith(f"py{major}") and py[3:].isdigit() and int(py[3:]) <= minor):
                rank = 900 if abi == "none" else None
        else:
            os_ok = ((sys.platform.startswith("linux") and plat.startswith(("manylinux", "linux")) and any(a in plat for a in arch))
                     or (sys.platform == "darwin" and plat.startswith("macosx") and (any(a in plat for a in arch) or "universal2" in plat))
                     or (sys.platform == "win32" and plat in ("win32", "win_amd64", "win_arm64")
                         and (plat == "win32" or any(a in plat for a in arch))))
            if os_ok and py == f"cp{major}{minor}" and abi in (py, "abi3", "none"):
                rank = 100
            elif os_ok and abi == "abi3" and py.startswith(f"cp{major}") and py[3:].isdigit() and int(py[3:]) <= minor:
                rank = 200
        if rank is not None and (best is None or rank < best):
            best = rank
    return best


def wheel_rank(filename: str) -> int | None:
    lib = _tag_library()
    return _rank_with_library(lib, filename) if lib else _rank_heuristic(filename)


def choose(files: list[dict], policy: str = POLICY_INSTALLED) -> tuple[dict | None, str, str]:
    """(chosen release file, kind 'wheel'|'sdist', reason). `files` are PyPI JSON release file dicts."""
    sdist = next((f for f in files if f.get("packagetype") == "sdist"), None)
    wheels = [f for f in files if f["filename"].endswith(".whl")]
    if policy == POLICY_SDIST_FIRST:
        pure = next((f for f in wheels if f["filename"].endswith("-none-any.whl")), None)
        if sdist or pure:
            pick = sdist or pure
            return pick, ("sdist" if pick is sdist else "wheel"), "sdist_first policy"
        if wheels:
            return min(wheels, key=lambda f: f.get("size") or 0), "wheel", "sdist_first policy: smallest wheel"
        return None, "", "no release files"
    ranked = [(wheel_rank(f["filename"]), f.get("size") or 0, f) for f in wheels]
    compatible = sorted((r for r in ranked if r[0] is not None), key=lambda r: (r[0], r[1]))
    if compatible:
        return compatible[0][2], "wheel", "pip installs the compatible wheel"
    if sdist:
        return sdist, "sdist", "no compatible wheel: pip builds from the sdist (setup.py runs)"
    if wheels:
        return min(wheels, key=lambda f: f.get("size") or 0), "wheel", "no compatible wheel and no sdist: smallest wheel"
    return None, "", "no release files"
