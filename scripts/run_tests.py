#!/usr/bin/env python3
"""Run tests/test_*.py and guard/*/tests and print a summary. Exit code 1 if any fails.

  python3 scripts/run_tests.py            # all
  python3 scripts/run_tests.py -k npm     # only tests with npm in the name

"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-k", default="", help="pick tests whose file name contains this text")
    ap.add_argument("--timeout", type=int, default=300, help="time limit per file (seconds)")
    args = ap.parse_args()
    # On first run the guard records a checksum list of its own files (guard/aegis_manifest.json) and reports later changes
    # as possible tampering. Editing code is normal in a development folder, so each test run starts from a fresh list.
    (ROOT / "guard" / "aegis_manifest.json").unlink(missing_ok=True)
    jobs = [(f.name, [sys.executable, str(f)]) for f in sorted((ROOT / "tests").glob("test_*.py"))]
    # packages that keep their own tests folder inside the module run with unittest discover
    for pkg in sorted(p.parent for p in (ROOT / "guard").glob("*/tests")):
        jobs.append((f"guard/{pkg.name}/tests", [sys.executable, "-m", "unittest", "discover", "-s", str(pkg / "tests")]))
    jobs = [j for j in jobs if args.k in j[0]]
    # the guard keeps state under ~/.aegis (ack ids, indexes, MCP servers seen): tests get a home of their own so a run
    # never touches the developer's real one. Git still needs an identity for the tests that make commits.
    home = tempfile.mkdtemp(prefix="aegis-tests-home-")
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "HOME": home,
           "GIT_AUTHOR_NAME": "AegisPilot tests", "GIT_AUTHOR_EMAIL": "tests@example.invalid",
           "GIT_COMMITTER_NAME": "AegisPilot tests", "GIT_COMMITTER_EMAIL": "tests@example.invalid"}
    env.pop("CLAUDE_CONFIG_DIR", None)
    failed = []
    t0 = time.time()
    for name, cmd in jobs:
        try:
            p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=args.timeout, env=env)
            ok, tail = p.returncode == 0, (p.stdout + p.stderr)[-1500:]
        except subprocess.TimeoutExpired:
            ok, tail = False, f"exceeded {args.timeout}s"
        print(f"{'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failed.append(name)
            print("    " + tail.replace("\n", "\n    "))
    shutil.rmtree(home, ignore_errors=True)
    print(f"\n{len(jobs) - len(failed)}/{len(jobs)} passed ({time.time() - t0:.0f}s)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
