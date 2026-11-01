"""
AegisPilot - PyPI as a source: the project JSON and the release file pip would install (next to
sources/npm.py, repo.py, bundle.py, direct.py).

Nothing is run: the release file is downloaded and unpacked with safe_extract's limits (large wheels: only their Python
files, through HTTP Range - remote_wheel.py).
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

import safe_extract
import switches

# Download ceiling (bytes). Measured: tensorflow's smallest wheel (223 MB) takes ~56 s and
# ~335 MB RSS to scan before the speedups; 250 MB covers it and torch (124 MB). Anything larger is not
# read (the whole archive is held in memory) and is reported as unscanned, never silently passed.
MAX_DOWNLOAD_BYTES = 250 * 1024 * 1024

# Wheels at least this large are not downloaded whole: remote_wheel reads the zip's file table and fetches only the
# `.py`/`.pth` members with HTTP Range. Measured on real wheels (tensorflow 223 MB, torch 124 MB, ...): 5 large
# wheels 430 MB -> 44 MB transferred, 19 s -> 9 s, peak memory 323 MB -> 50 MB, identical scan results (7/7).
# Below this size the extra requests cost more than they save (pandas 7 MB: 1.2 s -> 1.6 s).
FILES_HOST = "https://files.pythonhosted.org/"         # release files are only fetched from PyPI's file host
RANGE_MIN_BYTES = 16 * 1024 * 1024
# which release file to read: "installed" = what pip installs (compatible wheel, else sdist), "sdist_first" = old behaviour
ARTIFACT_POLICY = switches.get("AEGIS_ARTIFACT_POLICY", "installed") or "installed"   # built guard: system config only

PYPI_JSON_URL = "https://pypi.org/pypi/{name}/json"


def metadata(name: str) -> dict:
    """The project's JSON document (every release and its files)."""
    with urllib.request.urlopen(PYPI_JSON_URL.format(name=name), timeout=15) as resp:
        return json.loads(resp.read())


def fetch(name: str, version: str | None, dest_dir: Path,
          info: dict | None = None, meta: dict | None = None) -> tuple[str | None, list[Path]]:
    """Download the release file pip would install (see artifact_select), unpack it, but never execute
    setup.py or any install script. Returns (resolved_version, list_of_extracted_file_paths).
    `info`, when given, receives {"artifact", "artifact_kind", "artifact_reason"}. `meta` (the project JSON) avoids a second request."""
    meta = meta or metadata(name)
    releases = meta.get("releases", {})
    resolved = version or meta.get("info", {}).get("version")
    if resolved not in releases or not releases[resolved]:
        return resolved, []

    # A release ships an sdist and/or many platform wheels. pip installs the compatible wheel and builds the
    # sdist only when there is none, so that is the file we read (artifact_select; AEGIS_ARTIFACT_POLICY=sdist_first
    # restores the old "sdist first" choice).
    import artifact_select
    candidates = releases[resolved]
    chosen, kind, reason = artifact_select.choose(candidates, ARTIFACT_POLICY)
    # the file name comes from registry JSON and is joined onto dest_dir: "../x" or "/abs/x" would write outside it
    # (seen in testing), so keep only the last path component
    chosen = dict(chosen, filename=os.path.basename(chosen["filename"].replace("\\", "/")) or "artifact")
    if not str(chosen.get("url") or "").startswith(FILES_HOST):
        raise ValueError("file address in the PyPI metadata is not files.pythonhosted.org")    # as npm.py does
    if info is not None:
        info.update(artifact=chosen["filename"], artifact_kind=kind, artifact_reason=reason)
    if chosen["filename"].endswith(".whl") and (chosen.get("size") or 0) >= RANGE_MIN_BYTES:
        try:
            import remote_wheel
            paths, _stats = remote_wheel.fetch_python_files(chosen["url"], dest_dir, chosen["filename"])
            unpacked = dest_dir / (chosen["filename"] + ".unpacked")
            if info is not None:
                info["skipped"] = _stats.get("skipped", [])
            return resolved, [p for p in unpacked.rglob("*")]       # python files + README name markers
        except safe_extract.ArchiveLimitError:
            raise         # a limit is a verdict (REVIEW: not analyzed), not something the full download should retry
        except Exception:
            pass          # an optimization only: any problem (Range ignored, odd zip) falls back to the full download
    if (chosen.get("size") or 0) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"package too large, code not scanned ({chosen['size'] / 1e6:.0f}MB > {MAX_DOWNLOAD_BYTES // 1024 // 1024}MB limit)")

    extracted: list[Path] = []
    for file_info in [chosen]:
        url = file_info["url"]
        filename = file_info["filename"]
        with urllib.request.urlopen(url, timeout=30) as resp:
            raw = resp.read(MAX_DOWNLOAD_BYTES + 1)     # metadata size can be wrong; enforce while reading
        if len(raw) > MAX_DOWNLOAD_BYTES:
            raise ValueError(f"package too large, code not scanned (>{MAX_DOWNLOAD_BYTES // 1024 // 1024}MB limit)")
        local_path = dest_dir / filename
        local_path.write_bytes(raw)
        if info is not None:
            info["archive_path"] = str(local_path)      # lets the ML stage read the same file instead of downloading again
            if info.get("archive_ready"):
                info["archive_ready"].set()

        root = dest_dir / (filename + ".unpacked")
        root.mkdir(parents=True, exist_ok=True)
        skipped: list = []
        # an sdist's build can run files that are not Python (Makefile, configure, a data file setup.py exec()s)
        aside = None if filename.endswith(".whl") else safe_extract.aside_dir(root)
        if filename.endswith(".whl") or filename.endswith(".zip"):
            safe_extract.extract_zip(raw, root, skipped, aside=aside)
        elif filename.endswith((".tar.gz", ".tgz")):
            safe_extract.extract_targz(raw, root, skipped, aside=aside)
        else:                       # .tar.bz2, .egg, ...: nothing would be read, which must not look like clean code
            raise ValueError(f"release file format not read ({filename}), code not scanned")
        extracted.extend(root.rglob("*"))
        if info is not None:
            info["skipped"] = skipped
    return resolved, extracted
