"""
AegisPilot - the per-source checks of an install decision.

Each module checks one kind of source and returns records (checks/base.py: Check, Outcome, Context):

  pypi          packages from PyPI, their previous releases, their dependencies       (sources/pypi.py)
  local_files   wheels / sdists on disk
  direct        git repositories and URLs                                              (sources/direct.py, repo.py)
  ecosystems    packages from other registries - npm                                   (sources/npm.py)
  bundles       files an agent extension runs: MCP server script, plugin, hook         (sources/bundle.py)
  npm_lock      every locked npm release against OSV's malicious records
  npm_script_deps  npm dependencies with install scripts
  unscanned     what the parser already knows it cannot read

run_all runs the ones with something to do side by side under one budget (so a command mixing sources waits for the
slowest, not for the sum); a check that does not finish records what it would have covered as not checked. The order
of REGISTRY is the order of the records (and so of the cards). A new source = a module here + a line below.
"""
from __future__ import annotations

import threading
import time

from checks import bundles, direct, ecosystems, local_files, npm, pypi, unscanned
from checks.base import Context, Outcome

REGISTRY = [pypi.CHECK, local_files.CHECK, direct.CHECK, ecosystems.CHECK, bundles.CHECK, npm.LOCK_MALICIOUS,
            npm.SCRIPT_DEPS, unscanned.CHECK]


def wanted(parsed) -> list:
    return [c for c in REGISTRY if c.wants(parsed)]


def run_all(ctx: Context, checks: list | None = None) -> list[tuple[str, Outcome]]:
    """[(check name, Outcome)] in registry order. Daemon threads: a check stuck in a download never keeps the hook
    process alive (hook_runtime ends with os._exit)."""
    todo = wanted(ctx.parsed) if checks is None else checks
    box: dict = {}
    errors: list = []

    def one(c):
        try:
            box[c.name] = c.run(ctx)
        except BaseException as e:                       # re-raised below: the hook's error net reports it (hook_runtime)
            errors.append(e)
    threads = [threading.Thread(target=one, args=(c,), daemon=True) for c in todo]
    for t in threads:
        t.start()
    for t in threads:
        t.join(max(0.0, ctx.deadline - time.monotonic()))
    if errors:
        raise errors[0]
    results = []
    for c in todo:
        out = box.get(c.name)
        if out is None:                                  # still running at the deadline
            out = c.on_timeout(ctx)
            out.report.setdefault("check_timeouts", []).append(c.name)
        results.append((c.name, out))
    return results
