"""
AegisPilot - hook runtime: deadline watchdog and last-resort error handling.

Why this exists (Claude Code hooks documentation, checked 2026-10-04):
  - A PreToolUse hook that reaches its `timeout` is cancelled, its output discarded, and the tool
    call proceeds. A hook that dies with an uncaught exception exits 1, which does not block
    either. Neither can be changed from inside the hook, and the hook event does not carry the
    configured timeout.
  - What the hook CAN do is finish on its own before the harness gives up, and turn its own
    failures into an explicit "ask" instead of a silent pass.

run() therefore (1) arms a watchdog that, at HOOK_DEADLINE_SECONDS, answers "confirm" (the scan did not
finish) and exits, and (2) catches any unexpected exception and answers "confirm" instead of crashing.
The answer is written in the agent's format by its adapter (adapters/); this module is the same for every agent.
Both only speak up when the event looks like something the guard is responsible for (an install
command, a guard/MCP file edit): a bug must not turn every `ls` into a popup.

Keep HOOK_DEADLINE_SECONDS above SCAN_BUDGET_SECONDS (scan_engine) and below the hook `timeout` in
settings (guard_cli.HOOK_TIMEOUT_SECONDS). The deadline can be overridden with the environment
variable AASM_HOOK_DEADLINE_SECONDS (used by the tests; also an escape hatch for slow machines).
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import traceback
import warnings
from typing import Callable
# package code is parsed, never run: its own SyntaxWarnings ("invalid escape sequence") are not ours to print
warnings.filterwarnings("ignore", category=SyntaxWarning)

HOOK_DEADLINE_SECONDS = 570.0

_lock = threading.Lock()
_finished = False


def text_or(fn_name: str, fallback: str, *args) -> str:
    """The new text from r4.text_format, or `fallback` (the previous wording) if that module cannot be loaded or raises.
    The confirmation text must never be able to take the gate down: a failed import in a hook exits 1, which does not block."""
    try:
        from r4 import text_format
        out = getattr(text_format, fn_name)(*args)
        return out if isinstance(out, str) and out.strip() else fallback
    except Exception:
        return fallback


def deadline_seconds() -> float:
    try:
        import switches          # a shorter deadline lets commands through unscanned: built guard = system config only
        return float(switches.get("AASM_HOOK_DEADLINE_SECONDS") or HOOK_DEADLINE_SECONDS)
    except ValueError:
        return HOOK_DEADLINE_SECONDS


_adapter = None
# the "if you approve ..." clause; the Korean form is matched too (older or localized message text)
_APPROVE_CLAUSE = re.compile(r"\s*(?:Approving|If (?:you )?approved?)[^.]*\.")
NO_CONFIRM_NOTE = " Refused because this agent cannot ask a person. If needed, a person should check it and run it themselves."


def refusal_text(reason: str) -> str:
    """A confirm text sent as a refusal: drop "if you approve ..." (nobody can approve) and say why it was refused."""
    return _APPROVE_CLAUSE.sub("", reason).rstrip() + NO_CONFIRM_NOTE


def set_adapter(adapter) -> None:
    global _adapter
    _adapter = adapter


def _current_adapter():
    if _adapter is None:
        from adapters import DEFAULT
        return DEFAULT
    return _adapter


def emit(action: str, reason: str) -> bool:
    """Write the decision for a core action (confirm / refuse; "ask" / "deny" are accepted as the same), once.
    An agent whose hook cannot ask a person gets a refusal for "confirm". False if a decision was already written."""
    global _finished
    adapter = _current_adapter()
    if action in ("confirm", "ask") and not getattr(adapter, "SUPPORTS_CONFIRM", True):
        action, reason = "refuse", refusal_text(reason)
    with _lock:
        if _finished:
            return False
        out = adapter.answer(action, reason)
        if out:
            print(out)
            sys.stdout.flush()
        _finished = True
        return True


def _finish() -> None:
    global _finished
    with _lock:
        _finished = True


def run(main: Callable[[dict], None], relevant: Callable[[dict], bool], label: str, adapter=None) -> None:
    """Read the hook event from stdin and run main(event) under the watchdog and the error net.

    relevant(event) says whether a failure on THIS event must be surfaced (it must be cheap and must
    not raise). Unreadable input falls through silently, as before (fail-open for what we cannot read).
    `adapter` writes the answers (default: Claude Code).
    """
    if adapter is not None:
        set_adapter(adapter)
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            return
    except Exception:
        return

    def surface(reason: str) -> None:
        try:
            if relevant(event):
                # AASM_FAIL_CLOSED=1: a guard that could not finish refuses instead of asking (opt-in; the default
                # is "ask"). Input the hook cannot read at all still falls through.
                if os.environ.get("AASM_FAIL_CLOSED", "0") == "1":
                    emit("refuse", reason.replace("Check it yourself before allowing.", "Blocked by the guard setting AASM_FAIL_CLOSED=1. A person should check it and run it themselves."))
                else:
                    emit("confirm", reason)
        except Exception:
            pass

    def on_deadline() -> None:
        surface(f"[AegisPilot] The scan did not finish within {deadline_seconds():g}s, so this command was not checked "
                f"({label}). Check it yourself before allowing. Details: /aegis")
        _finish()
        os._exit(0)

    timer = threading.Timer(deadline_seconds(), on_deadline)
    timer.daemon = True
    timer.start()
    try:
        main(event)
    except Exception as e:      # last resort: report it, never crash silently into a pass
        traceback.print_exc(file=sys.stderr)
        surface(f"[AegisPilot] Internal guard error ({type(e).__name__}): this command was not checked ({label}). "
                "Check it yourself before allowing. Details: /aegis")
    finally:
        timer.cancel()
        _finish()
        # End here once answered. Background threads (the OSV probe, the Profile) may still be inside network or SSL code;
        # letting the interpreter tear down around them crashed the process with SIGSEGV on the error path, and an exit that waited for them could outlast Claude Code's hook timeout.
        try:
            sys.stdout.flush()
            sys.stderr.flush()
        finally:
            os._exit(0)
