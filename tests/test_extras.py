"""Extras (`pkg[a,b]`): what they add installs too, so it is walked like any dependency (run: python3 tests/test_extras.py).
Every way an extra can be asked for goes through the same rule: the command line, a requirements file, pyproject.toml
(PEP 621 and poetry tables), a Pipfile, a local wheel, and a dependency's own requirement."""
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))

import collect as C  # noqa: E402
import install_parse  # noqa: E402
import project_deps  # noqa: E402
import transitive  # noqa: E402

FASTAPI = ["anyio>=3", "starlette<1", "uvicorn[standard]>=0.12; extra == 'standard'", "httpx; extra == 'Standard'",
           "fastapi[standard]; extra == 'all'", "orjson; extra == 'all'", "pytest; extra == 'test'",
           "colorama; sys_platform == 'win32' and extra == 'standard'", "Jinja2>=3; python_version >= '3' and extra == 'standard'"]


def names(deps):
    return [d["name"] for d in deps]


class ParseRequires(unittest.TestCase):
    def test_plain_install_leaves_extras_out(self):
        self.assertEqual(names(C.parse_requires(FASTAPI, own="fastapi")), ["anyio", "starlette"])

    def test_extras_asked_for_are_added(self):
        got = C.parse_requires(FASTAPI, ["standard"], own="fastapi")
        self.assertEqual(names(got), ["anyio", "httpx", "jinja2", "starlette", "uvicorn"])
        self.assertEqual(next(d for d in got if d["name"] == "uvicorn")["extras"], ["standard"])

    def test_extra_names_compare_as_pep685(self):
        self.assertEqual(names(C.parse_requires(FASTAPI, ["STANDARD"], own="fastapi")),
                         names(C.parse_requires(FASTAPI, ["standard"], own="fastapi")))
        self.assertEqual(names(C.parse_requires(["a; extra == 'dev-tools'"], ["Dev_Tools"])), ["a"])

    def test_own_extras_are_followed(self):
        got = names(C.parse_requires(FASTAPI, ["all"], own="FastAPI"))
        self.assertEqual(got, ["anyio", "httpx", "jinja2", "orjson", "starlette", "uvicorn"])
        chain = ["p[web]; extra == 'all'", "p[server]; extra == 'web'", "gunicorn; extra == 'server'", "p[all]; extra == 'server'"]
        self.assertEqual(names(C.parse_requires(chain, ["all"], own="p")), ["gunicorn"])      # a loop ends

    def test_one_entry_per_name(self):
        got = C.parse_requires(["uvicorn>=0.1", "uvicorn[standard]>=0.12; extra == 'x'"], ["x"])
        self.assertEqual(got, [{"name": "uvicorn", "spec": ">=0.1,>=0.12", "extras": ["standard"]}])

    def test_requirement_text(self):
        self.assertEqual(C.requirement_text({"name": "uvicorn", "spec": ">=0.12", "extras": ["standard"]}), "uvicorn[standard]>=0.12")


class CommandAndFiles(unittest.TestCase):
    def parse(self, command, files=None):
        d = Path(tempfile.mkdtemp())
        for name, text in (files or {}).items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_text(text) if isinstance(text, str) else (d / name).write_bytes(text)
        return install_parse.parse_install_command(command, cwd=d)

    def test_command_line(self):
        p = self.parse('pip install "fastapi[standard]" "requests[socks, Security]>=2" flask')
        self.assertEqual(p.extras, {"fastapi": {"standard"}, "requests": {"socks", "security"}})
        p = self.parse('uv add "fastapi[standard]"')
        self.assertEqual(p.extras, {"fastapi": {"standard"}})
        p = self.parse('pipx install "black[d]@24.1.0"')
        self.assertEqual((p.packages, p.extras), ([("black", "24.1.0")], {"black": {"d"}}))

    def test_requirements_file(self):
        p = self.parse("pip install -r requirements.txt", {"requirements.txt": "uvicorn[Standard]==0.30.0 ; python_version > '3'\nrich\n"})
        self.assertEqual((p.packages, p.extras), ([("uvicorn", "0.30.0"), ("rich", None)], {"uvicorn": {"standard"}}))

    def test_pyproject_extras_and_self_reference(self):
        toml = ('[project]\nname = "App"\ndependencies = ["fastapi[standard]"]\n'
                '[project.optional-dependencies]\nDev = ["pytest"]\nall = ["app[dev, docs]"]\ndocs = ["mkdocs[i18n]"]\nunused = ["tox"]\n')
        p = self.parse("pip install -e '.[all]'", {"pyproject.toml": toml})
        self.assertEqual(sorted(n for n, _ in p.packages), ["fastapi", "mkdocs", "pytest"])
        self.assertEqual(p.extras, {"fastapi": {"standard"}, "mkdocs": {"i18n"}})
        p = self.parse("pip install '.[DEV]'", {"pyproject.toml": toml})
        self.assertEqual(sorted(n for n, _ in p.packages), ["fastapi", "pytest"])

    def test_poetry_and_pipfile_tables(self):
        toml = ('[tool.poetry.dependencies]\npython = "^3.10"\nuvicorn = {version = "^0.30", extras = ["standard"]}\n'
                'requests = [{version = "2.31.0", extras = ["socks"]}]\n')
        p = self.parse("poetry install", {"pyproject.toml": toml})
        self.assertEqual(p.extras, {"uvicorn": {"standard"}, "requests": {"socks"}})
        self.assertIn(("requests", "2.31.0"), p.packages)
        pipfile = '[packages]\nrequests = {version = "==2.31.0", extras = ["socks"]}\n'
        p = self.parse("pipenv install", {"Pipfile": pipfile})
        self.assertEqual(p.extras, {"requests": {"socks"}})

    def test_local_wheel(self):
        meta = ("Metadata-Version: 2.1\nName: tool\nVersion: 1.0\nRequires-Dist: click\n"
                "Requires-Dist: rich ; extra == 'pretty'\nRequires-Dist: tool[pretty] ; extra == 'all'\n"
                "Requires-Dist: uvloop ; sys_platform == 'nonexistent'\n")
        buf = Path(tempfile.mkdtemp()) / "tool-1.0-py3-none-any.whl"
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("tool-1.0.dist-info/METADATA", meta)
        p = self.parse(f"pip install '{buf}[all]'")
        self.assertEqual(sorted(n for n, _ in p.packages), ["click", "rich"])
        p = self.parse(f"pip install '{buf}'")
        self.assertEqual(sorted(n for n, _ in p.packages), ["click"])


def meta(version, requires):
    return {"info": {"version": version, "requires_dist": requires},
            "releases": {version: [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}]}}


INDEX = {
    "uvicorn": meta("0.30.0", ["click", "uvloop; extra == 'standard'", "websockets; extra == 'standard'"]),
    "click": meta("8.1.0", []), "uvloop": meta("0.19.0", []), "websockets": meta("12.0", []),
    "starlette": meta("0.37.0", ["anyio", "uvicorn[standard]; extra == 'full'"]),
    "anyio": meta("4.0.0", []), "sse": meta("1.0", ["uvicorn"]),
}


class Walk(unittest.TestCase):
    def test_dependency_extras_are_walked(self):
        direct = [{"name": "app", "version": "1", "dependencies": [{"name": "uvicorn", "spec": "", "extras": ["standard"]}]}]
        found, _ = transitive.walk(direct, INDEX.__getitem__)
        self.assertEqual(sorted(r["name"] for r in found), ["click", "uvicorn", "uvloop", "websockets"])

    def test_met_again_with_more_extras(self):
        """A plain `uvicorn` first, then `starlette[full]` asks for `uvicorn[standard]`: listed once, extras walked."""
        direct = [{"name": "app", "version": "1", "dependencies": [
            {"name": "sse", "spec": "", "extras": []}, {"name": "starlette", "spec": "", "extras": ["full"]}]}]
        found, _ = transitive.walk(direct, INDEX.__getitem__)
        got = sorted(r["name"] for r in found)
        self.assertEqual(got, ["anyio", "click", "sse", "starlette", "uvicorn", "uvloop", "websockets"])
        self.assertEqual(len(got), len(set(got)))

    def test_direct_package_asked_again_with_extras(self):
        direct = [{"name": "uvicorn", "version": "0.30.0", "extras": [], "dependencies": [{"name": "click", "spec": "", "extras": []}]},
                  {"name": "app", "version": "1", "dependencies": [{"name": "uvicorn", "spec": "", "extras": ["standard"]}]}]
        found, _ = transitive.walk(direct, INDEX.__getitem__)
        self.assertEqual(sorted(r["name"] for r in found), ["click", "uvloop", "websockets"])


if __name__ == "__main__":
    unittest.main()
