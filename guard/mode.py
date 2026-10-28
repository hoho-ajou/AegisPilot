"""
AegisPilot - which of the two modes is on.

  user  (default) the guard shows its reasons to the person: fixed-format report, the person verifies and decides.
  auto            for unattended runs, turned on by the person: the guard records its reasons internally, the person gets
                  one short line, and Claude gets the evidence and decides itself (which dependency is the problem, what
                  to do instead). Actions on the guard itself still ask the person (guard_core._ask always_ask).

The choice decides how much a person is in the loop, so it is protected like the other guard settings: it is read from the
environment (set by the person in their settings) or from .aegis/policy.json, which is a protected path (an agent that
edits it triggers a REVIEW). Nothing configured -> user, so a deleted or missing policy file never takes the
person out of the loop. Something configured but unusable (a typo in the environment, a
damaged policy file) -> user: a mistake must never quietly reduce what the person gets to see.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

MODES = ("user", "auto")


DEFAULT_MODE = "user"


def get_mode(project_dir: str | os.PathLike | None = None, env=None) -> str:
    env = os.environ if env is None else env
    raw = str(env.get("AEGIS_MODE", "")).strip().lower()
    if raw:
        return raw if raw in MODES else "user"                      # set but unknown: the cautious mode
    if project_dir:
        policy = Path(project_dir) / ".aegis" / "policy.json"
        try:
            text = policy.read_text(encoding="utf-8")
        except FileNotFoundError:
            return DEFAULT_MODE                                       # no policy file: the default
        except OSError:
            return "user"
        try:
            data = json.loads(text)
            value = str(data.get("mode", "")).strip().lower() if isinstance(data, dict) else ""
        except ValueError:
            value = ""
        return value if value in MODES else "user"                   # present but unusable: the cautious mode
    return DEFAULT_MODE
