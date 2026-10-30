"""
AegisPilot - a git repository as a source: what a plugin's marketplace entry points at.

  GitHub        the archive of the pinned commit (codeload.github.com/<owner>/<repo>/tar.gz/<sha|ref>) - an HTTP download
                unpacked with safe_extract's limits, no git involved
  other https   `git fetch --depth 1` of the pinned commit into an empty repository: no checkout hooks (core.hooksPath
                is emptied), no LFS smudge filter, no submodules, no credential prompts, https only

Nothing in the repository is run. A pinned commit (`sha`) is what Claude Code installs too, so what is scanned is what
gets installed; without one the default branch is fetched and the commit is reported.
"""
from __future__ import annotations

import os
import re
import subprocess
import urllib.request
from pathlib import Path

TIMEOUT = 120
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
# kept from a repository archive: code of every language the rules read and text an agent reads
KEEP_SUFFIXES = (".py", ".pth", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".json", ".md",
                 ".yaml", ".yml", ".toml", ".txt")
_GITHUB = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")
_REF = re.compile(r"^\w[\w./-]{0,199}$")          # never starts with "-": git would read it as an option


def github_repo(url: str) -> str | None:
    m = _GITHUB.match(url or "")
    return f"{m.group(1)}/{m.group(2)}" if m else None


ALL_FILES = ("",)                                        # every member (a guard release is checked file by file)


def fetch_github(repo: str, ref: str | None, dest: Path, keep: tuple = KEEP_SUFFIXES) -> Path:
    """The unpacked archive's top folder for owner/repo at ref (a commit, tag or branch; None = default branch).
    keep: the file suffixes kept (ALL_FILES = everything)."""
    import safe_extract
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or (ref and not _REF.match(ref)):
        raise ValueError(f"could not parse the repository name: {repo}@{ref}")
    url = f"https://codeload.github.com/{repo}/tar.gz/{ref or 'HEAD'}"
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        raw = resp.read(MAX_ARCHIVE_BYTES + 1)
    if len(raw) > MAX_ARCHIVE_BYTES:
        raise ValueError(f"repository too large, not scanned (>{MAX_ARCHIVE_BYTES >> 20}MB)")
    root = dest / f"{repo.replace('/', '__')}.tgz.unpacked"
    root.mkdir(parents=True, exist_ok=True)
    skipped: list = []
    safe_extract.extract_targz(raw, root, skipped, keep)
    tops = [p for p in root.iterdir() if p.is_dir()]
    return tops[0] if len(tops) == 1 else root


def fetch_git(url: str, ref: str | None, dest: Path) -> Path:
    """A working tree of url at ref, fetched without running anything from the repository."""
    if not url.startswith("https://") or any(c in url for c in " \n\t"):
        raise ValueError("only https addresses are accepted")
    if ref and not _REF.match(ref):
        raise ValueError(f"could not parse the ref: {ref}")
    from sources import direct
    direct.check_host(url)                               # not this machine / the metadata service (see check_host)
    work = dest / "repo"
    work.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_CONFIG_NOSYSTEM": "1"}
    safe = ["-c", f"core.hooksPath={os.devnull}", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
            "-c", "submodule.recurse=false", "-c", "core.symlinks=false"]

    def git(*args):
        subprocess.run(["git", *safe, *args], cwd=work, env=env, check=True, timeout=TIMEOUT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    git("init", "-q")
    git("fetch", "-q", "--depth", "1", "--no-tags", "--", url, ref or "HEAD")
    git("checkout", "-q", "FETCH_HEAD")
    return work


def fetch(url: str, ref: str | None, dest: Path, subdir: str | None = None, keep: tuple = KEEP_SUFFIXES) -> Path:
    """The folder a plugin source points at: the repository (GitHub archive, else git), then `subdir` inside it."""
    repo = github_repo(url)
    root = fetch_github(repo, ref, dest, keep) if repo else fetch_git(url, ref, dest)
    if subdir:
        target = (root / subdir).resolve()
        if root.resolve() not in target.parents and target != root.resolve():
            raise ValueError("subpath points outside the repository")
        if not target.is_dir():
            raise ValueError(f"no '{subdir}' folder in the repository")
        return target
    return root
