#!/bin/sh
# SessionStart hook of the plugin: every check runs on python3 3.11+, so say once at session start when it is missing,
# and say when the guard is also installed another way (hooks in a settings file, a system install): each check would
# run twice. A file rather than an inline `python3 -c` in hooks.json: the plugin directory refuses inline programs.
if ! python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' 2>/dev/null; then
  echo '[AegisPilot] python3 (3.11 or later) not found, so install checks are not running. Install Python 3.11 or later.'
  exit 0
fi
python3 -I "$(dirname "$0")/../install_state.py" --session 2>/dev/null
exit 0
