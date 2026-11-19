"""
AegisPilot - scanning several packages of one install command in separate processes.

scan_engine.scan_packages runs the packages on threads. Static analysis is CPU work, and Python threads share one CPU
(GIL), so big packages barely gain. Measured on a 2-core server, single-shot like the hook (process start
included, ML off):

                    threads    forkserver   fork
    1 package        0.80s       0.97s      0.83s
    10 small        ~2.1s       ~2.2s      ~2.2s
    6 big            4.1s        3.1s       2.8s

So: processes only when a command has PROCESS_MIN_PACKAGES or more, through "forkserver" (a clean server process forks
the workers; plain fork is faster but unsafe here - the hook already runs a deadline watchdog and the Profile thread,
and forking a process that has threads can deadlock the child). Processes also let a scan stuck past the budget be
killed, which threads cannot be.

Kept on threads (scan_engine.scan_packages): fewer packages, ML on (every process would load the model again: seconds
each), AEGIS_SCAN_PROCESSES=0, or any failure to start the pool. Verdicts are the same either way (measured: identical).
"""
from __future__ import annotations

import os
import time

PROCESS_MIN_PACKAGES = 3


def _scan_one(item, project_dir=None):
    """One package in a worker process. With the command's project folder it reads and adds to the same verdict cache
    as the parent (verdict_cache merges what parallel writers add)."""
    import scan_engine
    name, version = item
    cache = None
    if project_dir:
        try:
            import verdict_cache as cache
            cache.begin(project_dir)
        except Exception:
            cache = None
    try:
        return scan_engine.scan_package(name, version)
    except Exception as e:                        # a crash is a finding, not a pass (same as the thread path)
        f = scan_engine.ScanFeatures(name=name, version=version, fetch_error=f"scan error: {e}")
        return scan_engine.Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"scan error: {e}"], f)
    finally:
        if cache is not None:
            cache.end()


def _use_processes(items) -> bool:
    if len(items) < PROCESS_MIN_PACKAGES or os.environ.get("AEGIS_SCAN_PROCESSES", "1") == "0":
        return False
    try:
        from ml_bridge import ml_enabled
    except ImportError:
        return True                                   # no ML model installed: nothing to keep in one process
    try:
        return not ml_enabled()
    except Exception:
        return False


def scan_packages(items, budget: float | None = None, workers: int | None = None):
    import scan_engine
    budget = scan_engine.SCAN_BUDGET_SECONDS if budget is None else budget
    workers = scan_engine.SCAN_WORKERS if workers is None else workers
    if not _use_processes(items) or getattr(scan_engine.scan_packages, "__module__", "scan_engine") != "scan_engine":
        return scan_engine.scan_packages(items, budget=budget, workers=workers)   # (a replaced scan_packages, e.g. in tests, is honoured)
    try:
        import multiprocessing as mp
        from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
        ctx = mp.get_context("forkserver")
        ctx.set_forkserver_preload(["scan_engine", "scan_parallel"])
        ex = ProcessPoolExecutor(max(1, min(workers, len(items))), mp_context=ctx)
    except Exception:
        return scan_engine.scan_packages(items, budget=budget, workers=workers)
    started = time.monotonic()
    futures = []
    try:
        # forkserver children re-import the main script by path; a caller without an `if __name__ == "__main__"` guard
        # (found in our own test) would then fail in every child. Hiding the path while the workers start makes
        # multiprocessing treat __main__ like an interactive session and skip that import; it is restored right after.
        import sys
        main = sys.modules.get("__main__")
        main_file = getattr(main, "__file__", None)
        try:
            if main_file is not None:
                del main.__file__
            project_dir = None
            try:
                import verdict_cache
                project_dir = verdict_cache.current_dir()
            except Exception:
                pass
            futures = [ex.submit(_scan_one, item, project_dir) for item in items]
        finally:
            if main_file is not None:
                main.__file__ = main_file
        # wait piece by piece: a BLOCK here, or the command's stop from another check, ends the wait - the command is
        # refused either way, and the packages not finished are REVIEWs that say so (scan_engine.COMMAND_STOP)
        pending, stopped = set(futures), False
        while pending:
            left = budget - (time.monotonic() - started)
            if left <= 0:
                break
            done, pending = wait(pending, timeout=min(left, 0.5), return_when=FIRST_COMPLETED)
            for fut in done:
                try:
                    if fut.exception() is None and fut.result().verdict == "BLOCK":
                        scan_engine.command_blocked()
                except Exception:
                    pass
            if scan_engine.COMMAND_STOP.is_set():
                stopped = True
                break
        out = []
        for (name, version), fut in zip(items, futures):
            if fut.done() and not fut.cancelled() and fut.exception() is None:
                out.append(fut.result())
            elif stopped and not fut.done():
                out.append(scan_engine._command_stopped(scan_engine.ScanFeatures(name=name, version=version)))
            elif fut.done() and fut.exception() is not None:
                e = fut.exception()
                f = scan_engine.ScanFeatures(name=name, version=version, fetch_error=f"scan error: {e}")
                out.append(scan_engine.Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"scan error: {e}"], f))
            else:
                f = scan_engine.ScanFeatures(name=name, version=version, fetch_error=f"scan timed out ({budget:.0f}s)")
                out.append(scan_engine.Verdict("NEEDS_HUMAN_REVIEW", 0.5, [f"scan timed out ({budget:.0f}s) - not checked"], f))
        return out
    finally:
        for fut in futures:
            fut.cancel()
        procs = list(getattr(ex, "_processes", {}).values())
        ex.shutdown(wait=False, cancel_futures=True)
        for p in procs:                           # a scan stuck past the budget is ended, not left running
            try:
                if p.is_alive():
                    p.terminate()
            except Exception:
                pass
