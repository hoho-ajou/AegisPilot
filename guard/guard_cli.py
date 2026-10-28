#!/usr/bin/env python3
"""AegisPilot - setup helper.

  python3 guard/guard_cli.py installs   every AegisPilot install found here; in a terminal, choose the one to keep
  python3 guard/guard_cli.py snippet    print the `hooks` block for .claude/settings.json with this
                                       checkout's absolute paths (it never writes any settings file)
  python3 guard/guard_cli.py snippet codex
                                       the same for Codex CLI (<repo>/.codex/hooks.json)
  python3 guard/guard_cli.py profile [--project DIR] [--env-names]
                                       what this agent environment can do and reach (no secret values are read)
  python3 guard/guard_cli.py paths [--project DIR] [--decision D7f3a] [--judge] [--json]
                                       attack paths from the last guard decision and the environment Profile;
                                       --judge prints the CVE-judgement request for the agent when some are pending
  python3 guard/guard_cli.py selftest   feed sample Bash events to the hook and show what it decides
  python3 guard/guard_cli.py verify     is this guard what was built? (read-only; exit 1 when files changed)
  python3 guard/guard_cli.py repair [--from DIR] [--target DIR] [--dry-run] [--yes]
                                        put the guard back to its official build (--yes: no typed confirmation)
  python3 guard/guard_cli.py ack <id>   auto mode: go on with the action the guard stopped (the same action passes once)
  sudo python3 guard/guard_cli.py system-install [--prefix DIR] [--managed-hooks-only] [--dry-run]
                                        root-owned install + Claude Code hooks pinned in managed settings
  sudo python3 guard/guard_cli.py system-uninstall [--prefix DIR]
                                       (network needed: PyPI + OSV; changes no Claude Code setting)
"""
import os
import sys

# The guard folder goes AFTER the standard library and before site-packages: first on the path, a file
# named like a standard module (json.py) planted next to the guard would be imported instead of it. Only sys and os
# (loaded by Python at start) are used before this line.
_GUARD = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) not in (_GUARD, os.path.join(_GUARD, "hooks"))]
sys.path.insert(next((i for i, p in enumerate(sys.path) if p.endswith(("site-packages", "dist-packages"))), len(sys.path)), _GUARD)

import json
import re
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent
HOOK_TIMEOUT_SECONDS = 600      # the scan budget is 540s (scan_engine.SCAN_BUDGET_SECONDS); keep this above it


# -I: isolated - no PYTHON* environment variables and no user site-packages, so a .pth that a `pip install --user`
# package dropped there (it runs in every Python of that user) does not run inside the guard. The guard uses
# the standard library only (ML runs in its own interpreter).
PY_FLAGS = "-I"


def snippet() -> dict:
    def hook(script: str) -> dict:
        return {"type": "command", "command": f"python3 {PY_FLAGS} {HERE / 'hooks' / script}", "timeout": HOOK_TIMEOUT_SECONDS}
    return {"hooks": {"PreToolUse": [
        {"matcher": "Bash", "hooks": [hook("pretooluse_check.py")]},
        {"matcher": "Edit|MultiEdit|Write", "hooks": [hook("pretooluse_editwrite_check.py")]},
    ]}}


def codex_snippet() -> dict:
    hook = {"type": "command", "command": f"python3 {PY_FLAGS} {HERE / 'hooks' / 'codex_pretooluse.py'}", "timeout": HOOK_TIMEOUT_SECONDS}
    return {"hooks": {"PreToolUse": [{"matcher": "^(Bash|apply_patch)$", "hooks": [hook]}]}}


# (command, what the guard should do) - expectations hold at the time of writing (2026-10); they depend on
# live PyPI/OSV data, so a mismatch is a prompt to look, not proof of a bug.
# (command, expected decision, why[, mode]): `user` mode is the person-facing contract (REVIEW asks); `auto` has no person, so a REVIEW is a card
SAMPLES = [
    ("pip install pyyaml==5.3.1", "deny", "CRITICAL CVE -> BLOCK"),
    ("pip install requests==2.31.0", "ask", "old pinned version with CVEs -> REVIEW popup"),
    ("pip install requests==2.31.0", "deny", "auto mode: the same REVIEW is handed to the agent as a card, nobody is asked", "auto"),
    ("pip install requests>=2", "pass", "latest requests is clean -> ALLOW (silent)"),
    ("pip install git+https://github.com/x/y.git", "ask", "VCS source cannot be scanned -> REVIEW"),
    ("pip install --index-url https://private.example/simple requests", "ask", "custom index -> REVIEW"),
    ("uv sync", "ask", "project install with no project files to read -> REVIEW (never a silent pass)"),
    ("npm install left-pad", "pass", "npm package scanned (2026-10-23), nothing found"),
    ("ls -la", "pass", "not an install command"),
]


def verify() -> int:
    """Read-only: is this guard what was built? (exit 0 yes, 1 no). An agent may run it; it changes nothing."""
    import integrity
    if not integrity.released():
        print("Development folder (not a built guard): comparing against the baseline made on first run instead of build-time checksums.")
    else:
        try:
            info = json.loads(integrity.BUILD_INFO.read_text())
            print(f"Build: {info.get('channel')} {str(info.get('commit', ''))[:12]} ({info.get('built_at')})")
        except (OSError, ValueError):
            print("Could not read build info (BUILD_INFO.json)")
    import switches
    for name in switches.ignored():
        print(f"  Env var {name} ignored: settings that weaken checks are read only from the config file (~/.aasm/config.json, admins: /etc/aasm/config.json)")
    for line in rule_module_lines():
        print(line)
    findings = integrity.check_integrity()
    for f in findings:
        print(f"  - {f}")
    if findings:
        print(f"{len(findings)} guard file(s) differ from the build. If you did not change them yourself, restore the official version"
              f" (python3 -I {HERE / 'guard_cli.py'} repair, add --yes outside a terminal).")
        return 1
    print("Guard files match the build.")
    return 0


def rule_module_lines() -> list[str]:
    """What the rule modules on top of the base rules are doing (rule_modules.py): applied, or skipped and why."""
    try:
        import rule_engine
        mods = rule_engine.current().modules
    except Exception as e:                               # the base rules themselves: integrity / repair says more
        return [f"  Could not load rules: {type(e).__name__}: {e}"]
    if not mods:
        return []
    out = [f"Rule modules: {sum(m['status'] == 'applied' for m in mods)} applied, {sum(m['status'] != 'applied' for m in mods)} skipped:"]
    for m in mods:
        who = "admin" if m["origin"] == "admin" else "user"
        if m["status"] == "applied":
            what = ", ".join(f"{k} {v}" for k, v in (m.get("changes") or {}).items()) or "no changes"
            out.append(f"  + [{who}] {m.get('name')} ({m['file']}): {what}")
        else:
            out.append(f"  - [{who}] {m.get('name', '')} ({m['file']}): skipped - {m.get('error')}")
    return out


def repair_cmd(argv: list[str]) -> int:
    """Restore the official files (repair.py): the source is the official commit (or --from), checked against its own
    checksums; what is replaced is kept in ~/.aasm/quarantine. A person confirms at a terminal; an agent in auto mode
    runs it with --yes (recovering is part of the agent's work, not a stop). Safest: run it from a freshly
    downloaded official copy, `--target` the damaged install."""
    import argparse
    import repair
    ap = argparse.ArgumentParser(prog="guard_cli.py repair")
    ap.add_argument("--from", dest="src", type=Path, help="another build of the guard to restore from (default: the official commit)")
    ap.add_argument("--target", type=Path, default=HERE, help="the guard folder to repair (default: this one)")
    ap.add_argument("--dry-run", action="store_true", help="only show what would change")
    ap.add_argument("--yes", action="store_true", help="no typed confirmation (an agent in auto mode, scripts)")
    a = ap.parse_args(argv)
    if not a.dry_run and not a.yes and not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Outside a terminal, run with --yes (verify shows what changed, --dry-run shows what would be restored).")
        return 2
    target = a.target.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            src, files, origin = repair.prepare(target, a.src.resolve() if a.src else None, Path(tmp))
        except repair.RepairError as e:
            print(f"Could not repair: {e}")
            return 1
        todo = repair.plan(target, files)
        print(f"Restore from: {origin}\nTarget: {target}")
        for key, label in (("replace", "restore official file"), ("remove", "remove (not in the official version)"), ("add", "re-add")):
            for rel in todo[key][:20]:
                print(f"  {label}: {rel}")
        if not any(todo.values()):
            print("Target matches the source. Nothing to change.")
            return 0
        if a.dry_run:
            return 0
        if not a.yes and input("Type repair to restore as shown: ").strip() != "repair":
            print("Cancelled.")
            return 1
        q = repair.apply(target, src, todo, Path.home() / ".aasm" / "quarantine")
    import integrity
    left = integrity.check_release(target)
    print(f"Changed files were moved to {q}.")
    print("Check after repair: OK" if not left else f"{len(left)} file(s) still differ after repair: {left[:3]}")
    return 0 if not left else 1


def installs_cmd() -> int:
    """List every install of this guard; in a terminal, keep one and turn the others off (install_state.py)."""
    import install_state as st
    found = st.find(Path.cwd())
    if not found:
        print("No AegisPilot install found for this user and project.")
        return 0
    for n, item in enumerate(found, 1):
        print(f"  {n}. {st.describe(item)}")
    if len(found) == 1:
        print("One install: nothing to do.")
        return 0
    print("More than one install: every check runs once per install.")
    if not st.interactive():
        print("Nothing changed. Run this in a terminal to choose which one to keep.")
        return 1
    answer = input(f"Keep which one? [1-{len(found)}, Enter = keep all]: ").strip()
    if not answer.isdigit() or not 1 <= int(answer) <= len(found):
        print("Nothing changed.")
        return 0
    for n, item in enumerate(found, 1):
        if n != int(answer):
            print("  " + st.turn_off(item))
    return 0


def system_cmd(cmd: str, argv: list[str]) -> int:
    """system-install / system-uninstall (system_install.py). --root DIR puts every system path under DIR (tests)."""
    import argparse
    import system_install as si
    ap = argparse.ArgumentParser(prog=f"guard_cli.py {cmd}")
    ap.add_argument("--prefix", type=Path, default=si.DEFAULT_PREFIX)
    ap.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--managed-hooks-only", action="store_true",
                    help="allowManagedHooksOnly: only managed hooks run (turns off every user / project hook)")
    a = ap.parse_args(argv)
    if a.root is None and not a.dry_run and os.geteuid() != 0:
        print("System install must run as root (sudo). --dry-run shows what it would do.")
        return 2
    if cmd == "system-uninstall":
        removed = [] if a.dry_run else si.uninstall(a.prefix, a.root)
        print("\n".join(f"Removed: {r}" for r in removed) or "Nothing to remove (or --dry-run).")
        return 0
    try:
        p = si.plan(a.prefix, a.root, a.managed_hooks_only)
    except si.InstallError as e:
        print(f"Not installed: {e}")
        return 1
    if not a.dry_run and a.root is None:
        import install_state
        others = [i for i in install_state.find(None) if i["kind"] != "system"]
        if others and install_state.ask_skip_or_overwrite(others, "a system install") == "skip":
            return 0
    print(f"Guard: {p['source']} → {p['prefix']} (root-owned, read-only, precompiled)\n"
          f"Claude Code managed settings: {p['dropin']}\nSystem config: {p['config']} (only if missing)")
    if a.dry_run:
        print(json.dumps(p["dropin_doc"], ensure_ascii=False, indent=2))
        return 0
    si.install(p, root_owned=a.root is None)
    print("Installed. Check: python3 " + str(Path(p["prefix"]) / "guard_cli.py") + " verify")
    return 0


def decide(command: str, cwd: str, mode: str = "user") -> tuple[str, str]:
    event = json.dumps({"tool_name": "Bash", "cwd": cwd, "tool_input": {"command": command}})
    env = {**os.environ, "AASM_MODE": mode}
    out = subprocess.run([sys.executable, PY_FLAGS, str(HERE / "hooks" / "pretooluse_check.py")], input=event, env=env,
                         capture_output=True, text=True, timeout=HOOK_TIMEOUT_SECONDS).stdout.strip()
    if not out:
        return "pass", ""
    o = json.loads(out)["hookSpecificOutput"]
    return o["permissionDecision"], o["permissionDecisionReason"]


def selftest() -> int:
    bad = 0
    with tempfile.TemporaryDirectory() as cwd:
        for sample in SAMPLES:
            command, expect, why = sample[:3]
            mode = sample[3] if len(sample) > 3 else "user"
            got, reason = decide(command, cwd, mode)
            mark = "ok  " if got == expect else "DIFF"
            bad += got != expect
            print(f"[{mark}] {command}   [{mode}]\n       -> {got}  (expected {expect}: {why})")
            if reason:
                print("       " + reason.replace("\n", " ")[:170])
    print("\nselftest:", "all as expected" if not bad else f"{bad} differ - check network/PyPI/OSV before suspecting the code")
    return 1 if bad else 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "snippet":
        agent = sys.argv[2] if len(sys.argv) > 2 else "claude-code"
        if agent != "codex":
            import install_state
            existing = [i for i in install_state.find(Path.cwd())          # hooks of this same copy: a re-run, not a second install
                        if not (i["kind"] == "settings" and all(str(HERE) in c for c in i["commands"]))]
            if existing and install_state.ask_skip_or_overwrite(existing, "adding these hooks") == "skip":
                sys.exit(0)
        print(json.dumps(codex_snippet() if agent == "codex" else snippet(), indent=2, ensure_ascii=False))
    elif cmd == "installs":
        sys.exit(installs_cmd())
    elif cmd == "paths":
        import argparse
        import attack_path as AP
        ap = argparse.ArgumentParser(prog="guard_cli.py paths")
        ap.add_argument("--project", default=".")
        ap.add_argument("--judge", action="store_true")
        ap.add_argument("--json", action="store_true")
        ap.add_argument("--decision", default=None, help="decision id (e.g. D7f3a). Default: the most recent decision")
        a = ap.parse_args(sys.argv[2:])
        project = Path(a.project).resolve()
        result = AP.run(project, decision_id=a.decision)
        if a.judge and result["pending_judgements"]:
            ids = [i for p in result["pending_judgements"] for i in p.get("vuln_ids") or []]
            print(AP.cve_judgement_request(project, result["pending_judgements"], AP.save_osv(project, ids)))
        elif a.json:
            print(json.dumps(result, ensure_ascii=False, indent=1))
        else:
            print(AP.report_text(result))
            # in testing, 1 of 3 agents went looking for the package's setup.py to explain a path (none was
            # installed). The report is the explanation; the package's own files are attacker-written text.
            print("(To the agent: show the report above as is. Do not look for or open the package's own files to explain it.)")
        try:                                   # keep the last result next to the guard's record (for reports / dashboard)
            (project / ".aasm" / "attack_paths").mkdir(parents=True, exist_ok=True)
            text = json.dumps(result, ensure_ascii=False, indent=1)
            if result.get("decision_id"):
                (project / ".aasm" / "attack_paths" / f"{result['decision_id']}.json").write_text(text)
            (project / ".aasm" / "attack_paths.json").write_text(text)
        except OSError:
            pass
    elif cmd == "profile":
        from env_profile import main as profile_main
        sys.exit(profile_main(sys.argv[2:]))
    elif cmd == "verify":
        sys.exit(verify())
    elif cmd == "repair":
        sys.exit(repair_cmd(sys.argv[2:]))
    elif cmd == "ack":
        # auto mode: the agent decided to go on with an action the guard stopped (acks.py); the same action then passes once
        import acks
        if len(sys.argv) != 3 or not re.fullmatch(r"[0-9a-f]{8}", sys.argv[2]):
            print("usage: guard_cli.py ack <8-char ack id>")
            sys.exit(2)
        ok, msg = acks.grant(sys.argv[2])
        print(msg)
        sys.exit(0 if ok else 1)
    elif cmd in ("system-install", "system-uninstall"):
        sys.exit(system_cmd(cmd, sys.argv[2:]))
    elif cmd == "selftest":
        sys.exit(selftest())
    elif cmd == "report":
        from output.render import load_last_review, terminal_report, write_md_report
        project_dir = Path.cwd()
        report = load_last_review(project_dir)

        if not report:
            print(".aasm/last_review.json not found")
            sys.exit(1)

        fmt = "tree"
        if "--format" in sys.argv:
            i = sys.argv.index("--format")
            if i + 1 < len(sys.argv):
                fmt = sys.argv[i + 1]

        if fmt == "tree":
            from output.render import full_terminal_report
            width = (report.get("surface") or {}).get("width")
            print(full_terminal_report(report, width) if "--full" in sys.argv else terminal_report(report, width))
        elif fmt == "md":
            try:
                path = write_md_report(
                    project_dir,
                    report,
                    force=True,
                )
            except Exception as e:                       # a damaged last_review.json must not end in a traceback
                print(f"report could not be written: {type(e).__name__}: {e}")
                sys.exit(1)
            print(f"Report generated: {path}")
        else:
            print("format must be tree or md")
            sys.exit(2)
    else:
        print(__doc__)
        sys.exit(2)
