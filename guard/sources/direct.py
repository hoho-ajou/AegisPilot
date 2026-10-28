"""
AegisPilot - packages installed straight from a git repository or a URL.

`pip install git+https://github.com/o/r@v1`, `pip install "x @ https://host/x-1.0.tar.gz"`, `npm install github:o/r`
skip the registry, so until now they were "not scanned" (REVIEW with nothing to go on). The installer fetches that code
and runs its build / install scripts, so the same code is fetched here (never run) and goes through the same rules:

  git     sources/repo.py: GitHub's archive of the ref, else `git fetch --depth 1` with hooks / LFS / submodules off.
          https only - ssh / git:// / hg / svn / bzr stay "not scanned"
  archive an https URL of a .whl / .tar.gz / .tgz / .zip, downloaded with a size limit and unpacked by safe_extract

parse_python / parse_npm turn an install argument into a source dict, or None when it is not one of these shapes (the
caller then keeps it as not scanned). The name-based checks (typosquat, new package, OSV, version history) are about a
registry project of that name, which is not what is installed, so - as for a local file - only the code is read.
"""
from __future__ import annotations

import re
import urllib.parse
import urllib.request
from pathlib import Path

MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
TIMEOUT = 60
_ARCHIVE = re.compile(r"\.(whl|tar\.gz|tgz|zip)$", re.I)
_REF = re.compile(r"^[\w./-]{1,200}$")


def _git(url: str, name: str | None) -> dict | None:
    """git+https://host/path(.git)[@ref][#egg=x&subdirectory=y]"""
    u = url[4:] if url.startswith("git+") else url
    if not u.startswith("https://"):
        return None
    base, _, frag = u.partition("#")
    opts = dict(urllib.parse.parse_qsl(frag))
    m = re.match(r"^(https://[^@\s]+?)(?:@([^@/\s][^@\s]*))?$", base)
    if not m:
        return None
    ref = m.group(2)
    if ref and not _REF.match(ref):
        return None
    subdir = opts.get("subdirectory")
    if subdir and (subdir.startswith("/") or ".." in Path(subdir).parts):
        return None
    return {"kind": "git", "url": m.group(1), "ref": ref, "subdir": subdir,
            "name": name or opts.get("egg") or re.sub(r"\.git$", "", m.group(1).rstrip("/").rsplit("/", 1)[-1])}


def _archive(url: str, name: str | None) -> dict | None:
    path = urllib.parse.urlparse(url).path
    if not url.startswith("https://") or not _ARCHIVE.search(path):
        return None
    return {"kind": "archive", "url": url, "file": Path(path).name, "name": name or Path(path).name}


def parse_python(spec: str) -> dict | None:
    """A pip requirement that is a git / URL source: `git+https://...`, `https://.../x.whl`, `name @ <either>`."""
    s = spec.strip().strip("'\"")
    name = None
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*@\s*(\S+)$", s)
    if m:
        name, s = m.group(1), m.group(2)
    if s.startswith("git+"):
        src = _git(s, name)
    elif s.startswith("https://"):
        src = _archive(s, name)
    else:
        src = None
    return dict(src, ecosystem="pypi") if src else None


def parse_npm(spec: str) -> dict | None:
    """An npm install argument that is a git / URL source: github:o/r[#ref], o/r[#ref], git+https://...[#ref],
    https://github.com/o/r(.git)[#ref], https://.../x.tgz."""
    s = spec.strip().strip("'\"")
    name = None
    m = re.match(r"^(@?[^@\s]+)@((?:git\+|github:|https://)\S+)$", s)        # alias@source
    if m:
        name, s = m.group(1), m.group(2)
    if s.startswith(("./", "../", "/", "~", "file:", "link:", "workspace:")):
        return None                                                          # a local folder / tarball
    base, _, ref = s.partition("#")
    ref = ref or None
    if ref and (ref.startswith("semver:") or not _REF.match(ref)):
        return None
    m = re.match(r"^(?:github:)?(\w[\w.-]*)/([\w.-]+?)(?:\.git)?$", base)
    if m and not base.startswith(("http", "git+")):
        return {"kind": "git", "url": f"https://github.com/{m.group(1)}/{m.group(2)}", "ref": ref, "subdir": None,
                "name": name or m.group(2), "ecosystem": "npm"}
    if base.startswith("git+https://") or (base.startswith("https://") and not _ARCHIVE.search(base)):
        u = base[4:] if base.startswith("git+") else base
        return {"kind": "git", "url": u, "ref": ref, "subdir": None,
                "name": name or re.sub(r"\.git$", "", u.rstrip("/").rsplit("/", 1)[-1]), "ecosystem": "npm"}
    if base.startswith("https://") and re.search(r"\.(tgz|tar\.gz)$", urllib.parse.urlparse(base).path):
        return dict(_archive(base, name), ecosystem="npm")
    return None


def shown(src: dict) -> str:
    return src["url"] + (f"@{src['ref']}" if src.get("ref") else "") + (f"#{src['subdir']}" if src.get("subdir") else "")


def download(src: dict, dest: Path) -> Path:
    """The archive of an "archive" source saved as dest/<file name>."""
    with urllib.request.urlopen(src["url"], timeout=TIMEOUT) as resp:
        raw = resp.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError(f"package file too large, code not scanned (>{MAX_ARCHIVE_BYTES >> 20}MB limit)")
    name = re.sub(r"[^\w.+-]", "_", src["file"])[:120]
    out = dest / name
    out.write_bytes(raw)
    return out


def checkout(src: dict, dest: Path) -> Path:
    """The folder of a "git" source (sources/repo.py: nothing in the repository is run)."""
    from sources import repo
    return repo.fetch(src["url"], src.get("ref"), dest, src.get("subdir"))
