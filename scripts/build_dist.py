#!/usr/bin/env python3
"""
Build what gets installed from guard/ (the source), and make release tags. Never edit a built folder by hand.

  python3 scripts/build_dist.py release  # make the release tag v<version> locally (a person pushes it). See "Plugin release"
  python3 scripts/build_dist.py plugin   # the folder a Claude Code plugin install gets, for trying it out
                                         #   (../agent-dependency-guard-plugin; committed HEAD only, tests must pass;
                                         #   --worktree --skip-tests to try uncommitted work)
  python3 scripts/build_dist.py stable   # a built guard for a manual install, from committed HEAD, all tests must pass
                                         #   (../agent-dependency-guard, or --out DIR)
  python3 scripts/build_dist.py test     # the same from the working files as they are (../agent-dependency-guard-test)
  python3 scripts/build_dist.py check    # is the stable build current? (exit 1 if guard/ changed since it was built)

Plugin release: this repository is itself the marketplace. The top-level .claude-plugin/marketplace.json has the plugin
aegis-pilot installed from this repository's guard/ folder (git-subdir), pinned to the release tag v<version>. That tag's
commit is on no branch: it is HEAD with guard/ replaced by the plugin build (including BUILD_INFO.json and
RELEASE_MANIFEST.json, without the files excluded from builds). So guard/ on the branch has no checksum files, and the
installed copy does.

BUILD_INFO.json in a built folder records which commit it was built from. RELEASE_MANIFEST.json records every file's
checksum at build time (the integrity baseline; it replaces trusting whatever was on disk at first run).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = {"stable": ROOT.parent / "agent-dependency-guard", "test": ROOT.parent / "agent-dependency-guard-test",
               "plugin": ROOT.parent / "agent-dependency-guard-plugin"}
PLUGIN_JSON = ROOT / "guard" / ".claude-plugin" / "plugin.json"
MARKETPLACE_JSON = ROOT / ".claude-plugin" / "marketplace.json"
# left out of builds: the ML model (guard/r3; models are not in git and are heavy, installed separately), the development
# server, the settings example, the machine-specific checksum list
EXCLUDE_TOP = {"r3", "mcp_server.py", "SETTINGS_SNIPPET.json", "aasm_manifest.json"}
EXCLUDE_NAMES = {"__pycache__", ".aasm"}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def keep(rel: Path) -> bool:
    return rel.parts[0] not in EXCLUDE_TOP and not (set(rel.parts) & EXCLUDE_NAMES) and rel.suffix != ".pyc"


def copy_worktree(dst: Path) -> None:
    src = ROOT / "guard"
    for f in src.rglob("*"):
        rel = f.relative_to(src)
        if f.is_file() and keep(rel):
            (dst / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dst / rel)


def copy_head(dst: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tar = Path(tmp) / "guard.tar"
        subprocess.run(["git", "archive", "--format=tar", "-o", str(tar), "HEAD", "guard"], cwd=ROOT, check=True)
        with tarfile.open(tar) as tf:
            tf.extractall(tmp, filter="data")
        src = Path(tmp) / "guard"
        for f in src.rglob("*"):
            rel = f.relative_to(src)
            if f.is_file() and keep(rel):
                (dst / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dst / rel)


def plugin_info() -> dict:
    """The plugin's own plugin.json plus where the marketplace takes it from (its entry's git-subdir source)."""
    plugin = json.loads(PLUGIN_JSON.read_text(encoding="utf-8"))
    market = json.loads(MARKETPLACE_JSON.read_text(encoding="utf-8"))
    entry = next(e for e in market["plugins"] if e["name"] == plugin["name"])
    return {**plugin, "marketplace": market["name"], "source_entry": entry["source"]}


def release_problems(rel: dict) -> list[str]:
    """Why a release tag cannot be made from HEAD now (empty list: it can)."""
    out = []
    if git("ls-files", "AGENTS.md", "docs/worklog"):   # pushing the tag pushes its parents: never the development history
        out.append("not made on the development branch (pushing the tag would publish the development history with it): "
                   "check out the public branch made by scripts/export_public.py and run it there")
    if git("status", "--porcelain", "--untracked-files=no", "--", "guard", ".claude-plugin"):
        out.append("uncommitted changes in guard/ or .claude-plugin/")
    src, tag = rel["source_entry"], f"v{rel['version']}"
    if src.get("ref") != tag or src.get("path") != "guard":
        out.append(f"marketplace.json source does not point at guard/ and {tag} (now {src.get('path')}, {src.get('ref')}): fix it with the version and commit")
    if subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}"], cwd=ROOT, capture_output=True).returncode == 0:
        out.append(f"tag {tag} already exists: bump version in plugin.json, change ref in marketplace.json to match, and commit")
    return out


def tag_release(build: Path, rel: dict) -> str:
    """Commit (on no branch) HEAD with guard/ replaced by the plugin build, and tag it v<version>. Uses a scratch index,
    so the working tree, the index and the branch are untouched. Returns the commit."""
    tag = f"v{rel['version']}"
    with tempfile.TemporaryDirectory() as tmp:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(tmp) / "index")}
        run = lambda *a, inp=None: subprocess.run(["git", *a], cwd=ROOT, env=env, input=inp, capture_output=True,
                                                   text=True, check=True).stdout.strip()
        run("read-tree", "HEAD")
        run("rm", "-r", "-q", "--cached", "guard")
        lines = []
        for f in sorted(build.rglob("*")):
            if f.is_file():
                blob = run("hash-object", "-w", str(f))
                mode = "100755" if f.stat().st_mode & 0o111 else "100644"
                lines.append(f"{mode} {blob}\tguard/{f.relative_to(build).as_posix()}")
        run("update-index", "--index-info", inp="\n".join(lines) + "\n")
        tree = run("write-tree")
        commit = run("commit-tree", tree, "-p", "HEAD", "-m", f"release {tag}: guard/ as installed (with checksums)")
    subprocess.run(["git", "tag", "-a", tag, commit, "-m", f"{rel['name']} {tag}"], cwd=ROOT, check=True)
    return commit


def stale_reason(out: Path | None = None) -> str | None:
    """Why the stable build is out of date, or None if it is current. Test: did guard/ change on the branch the stable
    build was made from? (Comparing with the current branch would warn on every feature branch.)"""
    out = out or DEFAULT_OUT["stable"]
    try:
        info = json.loads((out / "BUILD_INFO.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return f"stable build ({out}) is missing or was not made by build_dist.py"
    commit, branch = info.get("commit", ""), info.get("branch", "")
    try:
        git("cat-file", "-e", f"{commit}^{{commit}}")
        tip = git("rev-parse", branch)
    except subprocess.CalledProcessError:
        return f"stable build commit ({commit[:8]}) or branch ({branch}) cannot be found in this repository"
    changed = [f for f in git("diff", "--name-only", commit, tip, "--", "guard").splitlines() if f]
    if not changed:
        return None
    shown = ", ".join(f.removeprefix("guard/") for f in changed[:3]) + (f" +{len(changed) - 3} more" if len(changed) > 3 else "")
    return (f"{len(changed)} guard/ file(s) changed on {branch} since the stable build ({commit[:8]}) was made ({shown}). "
            "Hooks still decide with the old code → `python3 scripts/build_dist.py stable`")


def main() -> int:
    if sys.argv[1:2] == ["check"]:                  # only check whether the stable build is current (exit 0 current, 1 out of date)
        reason = stale_reason(Path(sys.argv[3]).resolve() if sys.argv[2:3] == ["--out"] and len(sys.argv) > 3 else None)
        print(reason or "stable build is current")
        return 1 if reason else 0
    ap = argparse.ArgumentParser(description="build the install folders")
    ap.add_argument("channel", choices=["stable", "test", "plugin", "release"])
    ap.add_argument("--out", type=Path)
    ap.add_argument("--force", action="store_true", help="overwrite a folder this script did not make")
    ap.add_argument("--skip-tests", action="store_true", help="test channel, and trial plugin builds (--worktree) only")
    ap.add_argument("--worktree", action="store_true", help="plugin channel: use the working files instead of HEAD (for trials)")
    args = ap.parse_args()
    rel = plugin_info() if args.channel in ("plugin", "release") else {}
    if args.channel == "release":
        problems = release_problems(rel)
        if problems:
            print("not creating the release tag: " + "; ".join(problems))
            return 1
        args.worktree = False
        scratch = Path(tempfile.mkdtemp())
        args.out = scratch / "plugin"
    out = (args.out or DEFAULT_OUT[args.channel]).resolve()

    if out.exists() and not (out / "BUILD_INFO.json").exists() and not args.force:
        print(f"{out} was not made by this script (no BUILD_INFO.json). Check its contents, then overwrite with --force.")
        return 1
    released = args.channel in ("stable", "release") or (args.channel == "plugin" and not args.worktree)
    if released:
        if git("status", "--porcelain", "--untracked-files=no", "--", "guard"):   # uncommitted new files are not in a HEAD build
            print("guard/ has uncommitted changes, not making the stable build. Commit them or use the test channel.")
            return 1
        if subprocess.run([sys.executable, str(ROOT / "scripts" / "run_tests.py")], cwd=ROOT).returncode != 0:
            print("tests failed, not making the stable build.")
            return 1
    elif not args.skip_tests:
        subprocess.run([sys.executable, str(ROOT / "scripts" / "run_tests.py")], cwd=ROOT)   # the test build is made even if tests fail

    new = out.with_name(out.name + ".building")
    shutil.rmtree(new, ignore_errors=True)
    new.mkdir(parents=True)
    (copy_head if released else copy_worktree)(new)
    if not rel and (ROOT / "packaging").is_dir():   # a manual install: the install guide and a .gitignore (the plugin keeps guard/README.md)
        shutil.copy2(ROOT / "packaging" / "README.md", new / "README.md")
        shutil.copy2(ROOT / "packaging" / "gitignore", new / ".gitignore")
    dirty = bool(git("status", "--porcelain", "--", "guard"))
    info = {"channel": args.channel, "commit": git("rev-parse", "HEAD"), "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
            "dirty": dirty if not released else False, "built_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    if rel:
        # installed from the release tag's guard/ (see the top of this file): `repair` takes that tag as the official copy
        info.update(layout="plugin", version=rel["version"], source=rel["repository"], ref=f"v{rel['version']}",
                    path="guard")
    else:
        try:                   # where `guard_cli.py repair` fetches this commit back from
            info["source"] = git("remote", "get-url", "origin")
        except subprocess.CalledProcessError:
            pass
    (new / "BUILD_INFO.json").write_text(json.dumps(info, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    # the integrity baseline, made HERE from what was built - not on first use from whatever is on disk then
    files = {str(f.relative_to(new)): hashlib.sha256(f.read_bytes()).hexdigest()
             for f in sorted(new.rglob("*")) if f.is_file() and f.name != "RELEASE_MANIFEST.json"}
    (new / "RELEASE_MANIFEST.json").write_text(json.dumps({"commit": info["commit"], "channel": args.channel,
                                                           "built_at": info["built_at"], "files": files},
                                                          ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    if args.channel == "release":
        commit = tag_release(new, rel)
        shutil.rmtree(out.parent, ignore_errors=True)
        print(f"release tag v{rel['version']} → {commit[:12]} (HEAD {info['commit'][:8]} with guard/ replaced by the installed copy, on no branch)")
        print(f"publish: git push origin v{rel['version']}  (push the branch too, so marketplace.json points at this tag)")
        return 0
    old = out.with_name(out.name + ".old")
    shutil.rmtree(old, ignore_errors=True)
    if out.exists():
        out.rename(old)
    new.rename(out)
    shutil.rmtree(old, ignore_errors=True)
    print(f"{args.channel} build done: {out}  (commit {info['commit'][:8]}{', with uncommitted changes' if info['dirty'] else ''})")
    if args.channel == "plugin":
        print(f"validate: claude plugin validate --strict {out}")
        print(f"try the plugin folder alone: claude --plugin-dir {out}  (marketplace installs use the release tag)")
    else:
        print(f"connect the hooks: python3 {out / 'guard_cli.py'} snippet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
