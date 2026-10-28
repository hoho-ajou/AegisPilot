"""The Claude Code plugin (2026-10-24, one repository since 2026-10-25): this repository is the marketplace, the plugin is
its guard/ folder taken at the release tag. Checks the manifest / marketplace / hooks files, the plugin build that the
release tag holds (scripts/build_dist.py plugin), the release tag itself, that a release archive restores through repair,
that the integrity check accepts what Claude Code adds to its plugin cache, and that the agent cannot switch the plugin
off quietly.
run: python3 tests/test_plugin_package.py"""
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "guard"
sys.path.insert(0, str(GUARD))
sys.path.insert(0, str(ROOT / "scripts"))
import build_dist  # noqa: E402
import guard_paths  # noqa: E402
import integrity  # noqa: E402
import repair  # noqa: E402
import safe_extract  # noqa: E402
from sources import repo  # noqa: E402

PLUGIN = json.loads((GUARD / ".claude-plugin" / "plugin.json").read_text())
MARKET = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
TAG = f"v{PLUGIN['version']}"


def words_outside_code(md: str) -> int:
    return len(re.sub(r"```.*?```", " ", md, flags=re.S).split())


class Sources(unittest.TestCase):
    """The committed plugin files, as the plugin directory's checks read them."""

    def test_marketplace_points_at_the_release_tag(self):
        entry = next(e for e in MARKET["plugins"] if e["name"] == PLUGIN["name"])
        self.assertEqual(entry["source"], {"source": "git-subdir", "url": PLUGIN["repository"] + ".git", "path": "guard",
                                           "ref": TAG})
        self.assertTrue(MARKET.get("description"))
        self.assertEqual(len(MARKET["plugins"]), 1)

    def test_manifest(self):
        self.assertRegex(PLUGIN["name"], r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
        for k in ("description", "author", "version", "homepage", "repository", "license"):
            self.assertTrue(PLUGIN.get(k), k)
        self.assertEqual(PLUGIN["license"], "Apache-2.0")
        self.assertEqual((GUARD / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())

    def test_hooks(self):
        hooks = json.loads((GUARD / "hooks" / "hooks.json").read_text())["hooks"]
        commands = [h["command"] for ev in hooks.values() for m in ev for h in m["hooks"]]
        for cmd in commands:          # the directory refuses inline programs and other variables in hook commands
            self.assertNotRegex(cmd, r"\s-c\s|\$\((?!\{)|\$[A-Za-z_]", cmd)
            script = re.search(r'"\$\{CLAUDE_PLUGIN_ROOT\}"/(\S+)', cmd).group(1)
            self.assertTrue((GUARD / script).is_file(), script)
        for script in ("pretooluse_check.py", "pretooluse_editwrite_check.py"):
            self.assertIn(f'python3 -I "${{CLAUDE_PLUGIN_ROOT}}"/hooks/{script}', commands)
        self.assertTrue(all(h.get("timeout", 0) >= 600 for m in hooks["PreToolUse"] for h in m["hooks"]))
        self.assertTrue((GUARD / "hooks" / "python_check.sh").stat().st_mode & 0o111)

    def test_readme(self):
        text = (GUARD / "README.md").read_text()
        self.assertGreaterEqual(words_outside_code(text), 40)
        self.assertIn(f"claude plugin install {PLUGIN['name']}@{MARKET['name']}", text)
        for host in ("pypi.org", "registry.npmjs.org", "api.osv.dev", "github.com"):   # what it sends, for the scan
            self.assertIn(host, text)


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.out = cls.tmp / "plugin"
        r = subprocess.run([sys.executable, str(ROOT / "scripts" / "build_dist.py"), "plugin", "--worktree", "--skip-tests",
                            "--out", str(cls.out)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_build_info_and_checksums(self):
        info = json.loads((self.out / "BUILD_INFO.json").read_text())
        self.assertEqual((info["layout"], info["version"], info["ref"], info["path"]), ("plugin", PLUGIN["version"], TAG, "guard"))
        self.assertEqual(info["source"], PLUGIN["repository"])
        files = json.loads((self.out / "RELEASE_MANIFEST.json").read_text())["files"]
        for rel in (".claude-plugin/plugin.json", "hooks/hooks.json", "hooks/python_check.sh", "README.md", "LICENSE",
                    "BUILD_INFO.json"):
            self.assertIn(rel, files)
        self.assertFalse(any(f.startswith(("mcp_server.py", ".gitignore")) for f in files))
        self.assertIn("AegisPilot", (self.out / "README.md").read_text())       # the plugin README, not the manual guide
        self.assertEqual(integrity.check_release(self.out), [])

    def test_plugin_cache_markers_are_not_tampering(self):
        """Claude Code writes `.in_use` into an installed plugin's cache folder (seen 2026-10-24); Python writes
        __pycache__. Neither is a finding; an added .py still is."""
        d = self.tmp / "cache-copy"
        shutil.copytree(self.out, d)
        (d / ".in_use").write_text("")
        (d / "__pycache__").mkdir(exist_ok=True)
        (d / "__pycache__" / "x.cpython-312.pyc").write_bytes(b"\0")
        self.assertEqual(integrity.check_release(d), [])
        (d / "evil.py").write_text("import os\n")
        self.assertEqual(len(integrity.check_release(d)), 1)

    def test_release_archive_restores(self):
        """repair on a plugin install takes the release tag: a GitHub-style archive of the repository (one top folder,
        dot files included), whose guard/ is the plugin build, must unpack whole and pass the build's own checksums."""
        buf = io.BytesIO()
        top = f"{PLUGIN['repository'].rsplit('/', 1)[1]}-{PLUGIN['version']}"
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            tf.add(self.out, arcname=f"{top}/guard")
            tf.add(ROOT / ".claude-plugin", arcname=f"{top}/.claude-plugin")
        root = self.tmp / "unpacked"
        root.mkdir()
        safe_extract.extract_targz(buf.getvalue(), root, [], repo.ALL_FILES)
        src = root / top
        self.assertTrue((src / "guard" / ".claude-plugin" / "plugin.json").exists())
        with mock.patch.object(repair, "fetch_release", return_value=src) as fr:
            got, files, where = repair.prepare(self.out, None, self.tmp / "work")
        fr.assert_called_once_with(PLUGIN["repository"], TAG, self.tmp / "work")
        self.assertEqual((got, where), (src / "guard", f"{PLUGIN['repository']}@{TAG}/guard"))
        self.assertIn("BUILD_INFO.json", files)

    def test_validates_with_claude_code(self):
        if not shutil.which("claude"):
            self.skipTest("claude CLI not found")
        for target in (self.out, ROOT):            # the plugin as installed, and this repository as the marketplace
            r = subprocess.run(["claude", "plugin", "validate", "--strict", str(target)], capture_output=True, text=True,
                               timeout=120)
            self.assertEqual(r.returncode, 0, f"{target}: {r.stdout}{r.stderr}")

    def test_disabling_the_plugin_is_protected(self):
        """The installed plugin knows its own plugin name and, from the plugin cache path, its marketplace."""
        cache = self.tmp / "home" / ".claude" / "plugins" / "cache" / "some-market" / PLUGIN["name"] / PLUGIN["version"]
        shutil.copytree(self.out, cache)
        code = ("import sys; sys.path.insert(0, sys.argv[1]); import guard_paths as g; "
                "print([g.command_disables_guard(c) for c in sys.argv[2:]])")
        name = PLUGIN["name"]
        cmds = [f"claude plugin disable {name}@some-market", "claude plugin marketplace remove some-market",
                f"claude plugin marketplace remove {MARKET['name']}", f"claude plugin install {name}@some-market",
                "claude plugin list", "claude plugin disable other@x"]
        r = subprocess.run([sys.executable, "-I", "-c", code, str(cache), *cmds], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "[True, True, True, False, False, False]", r.stdout + r.stderr)


class ReleaseTag(unittest.TestCase):
    """build_dist.tag_release on a scratch repository: the tag's guard/ is the build, the rest of the tree is HEAD's,
    and the branch, index and working tree are untouched."""

    def test_tag(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            git = lambda *a: subprocess.run(["git", "-C", str(t / "repo"), *a], capture_output=True, text=True,
                                            check=True).stdout.strip()
            (t / "repo" / "guard").mkdir(parents=True)
            (t / "repo" / "guard" / "a.py").write_text("a = 1\n")
            (t / "repo" / "guard" / "mcp_server.py").write_text("left out of builds\n")
            (t / "repo" / "README.md").write_text("dev\n")
            git("init", "-q")
            git("-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "dev")
            head = git("rev-parse", "HEAD")
            build = t / "build"
            (build / "hooks").mkdir(parents=True)
            (build / "a.py").write_text("a = 1\n")
            (build / "hooks" / "run.sh").write_text("#!/bin/sh\n")
            (build / "hooks" / "run.sh").chmod(0o755)
            (build / "BUILD_INFO.json").write_text("{}\n")
            with mock.patch.object(build_dist, "ROOT", t / "repo"), \
                    mock.patch.dict("os.environ", {"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                                                   "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t"}):
                commit = build_dist.tag_release(build, {"name": "p", "version": "9.9.9"})
            self.assertEqual(git("rev-parse", "v9.9.9^{commit}"), commit)
            self.assertEqual(git("rev-parse", f"{commit}^"), head)
            self.assertEqual(git("rev-parse", "HEAD"), head)
            self.assertEqual(git("status", "--porcelain"), "")
            self.assertEqual(sorted(git("ls-tree", "-r", "--name-only", commit).splitlines()),
                             ["README.md", "guard/BUILD_INFO.json", "guard/a.py", "guard/hooks/run.sh"])
            self.assertTrue(git("ls-tree", commit, "guard/hooks/run.sh").startswith("100755"))


class Protection(unittest.TestCase):
    def test_commands(self):
        name, market = PLUGIN["name"], MARKET["name"]
        hit = [f"claude plugin disable {name}@{market}", f"claude plugin uninstall {name}",
               f"cd x; claude plugin uninstall {name} --scope project", "claude plugin uninstall aegis-pilot",
               f"claude plugin marketplace remove {market}"]
        miss = ["claude plugin list", f"claude plugin install {name}@{market}",
                "claude plugin disable formatter@x", "echo claude && pip install x"]
        self.assertTrue(all(guard_paths.command_disables_guard(c) for c in hit))
        self.assertFalse(any(guard_paths.command_disables_guard(c) for c in miss))
        self.assertTrue(guard_paths.command_touches_protected_path(hit[0]))
        self.assertIn(str(guard_paths.GUARD_DIR) + "/", guard_paths.GUARD_FRAGMENTS)


if __name__ == "__main__":
    unittest.main()
