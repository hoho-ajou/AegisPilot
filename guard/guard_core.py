"""
AegisPilot - the tool-independent decision core.

Takes what an agent is about to do - a shell command, or a file write with its resulting text - and returns a Decision.
It knows nothing about any agent's event or answer format: reading the hook event and printing the answer is the
adapter's job (adapters/), and so are the agent's own config paths and surface detection, which reach this module only
through the `agent` argument.

Actions:
  allow    nothing found -> the adapter prints nothing and the command goes on
  confirm  a person should look (REVIEW in user mode, guard self-protection, integrity); an agent whose hook cannot ask
           a person answers this as a refusal (adapters/<agent>.SUPPORTS_CONFIRM)
  refuse   BLOCK, or auto mode's card for a REVIEW (no person in the loop: the agent gets the steps instead)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import index_config
import switches
from guard_paths import (command_changes_guard_install, command_touches_protected_path, file_path_is_mcp_config,
                         file_path_is_protected, path_is_guard_own, settings_change_disables_guard)
from install_parse import parse_install_command
from integrity import check_integrity
from review_report import (
    PREFIX, cap_line, clean, deny_block, one_liner, write_report,
)

from scan_parallel import scan_packages     # threads, or processes for 3+ packages (scan_parallel.py)

ALLOW, CONFIRM, REFUSE = "allow", "confirm", "refuse"


@dataclass
class Decision:
    action: str = ALLOW
    reason: str = ""
    detail: str = ""        # the person-facing report for a side channel (user-mode BLOCK); the adapter decides where


def _text_or(fn_name: str, fallback: str, *args) -> str:
    """The text from r4.text_format, or `fallback` if that module cannot be loaded or raises (it must never take the gate down)."""
    try:
        from r4 import text_format
        out = getattr(text_format, fn_name)(*args)
        return out if isinstance(out, str) and out.strip() else fallback
    except Exception:
        return fallback


# a deliberately crude, independent test (it must not depend on install_parse, which may be the thing
# that failed): does this command look like it installs packages?
_INSTALLISH = re.compile(r"\b(pip3?|pipx|pipenv|uv|poetry|pdm)\b[^|;&]*\b(install|add|sync|update|download|wheel)\b|\bpip-sync\b"
                         # setup.py installs, easy_install, conda family, `$VAR install`, aliases, python -c
                         r"|\bsetup\.py\b[^|;&]*\b(install|develop|bdist_wheel|bdist_egg|build|egg_info|sdist)\b|\beasy_install\b"
                         r"|\b(conda|mamba|micromamba|pixi)\b[^|;&]*\b(install|create|update|upgrade|add)\b"
                         # npm family
                         r"|\b(npm|yarn|pnpm|bun)\b[^|;&]*\b(install|i|add|ci|update|exec|x|dlx|create|init)\b|\b(npx|pnpx|bunx)\b"
                         r"|\$\{?\w+\}?\s+(install|add|sync)\b|\balias\s+\w+="
                         # commands that change where later installs come from
                         r"|\bpip[\d.]*\b[^|;&]*\bconfig\b|\bpoetry\b[^|;&]*\b(source|config)\b|\bpdm\b[^|;&]*\bconfig\b"
                         r"|\b(pip\.conf|pip\.ini|uv\.toml)\b")


def _extensions(command: str, agent) -> list:
    """Extensions a shell command adds: the running agent's own CLI (plugins, marketplaces, ...) plus `<agent> mcp add`
    of every agent agent_formats.json knows (an agent under one tool can register a server in another)."""
    if agent is None:
        from adapters import DEFAULT as agent
    fn = getattr(agent, "extension_commands", None)
    out = fn(command) if fn else []
    try:
        import agent_config
        seen = {(e["kind"], e["name"]) for e in out}
        out += [e for e in agent_config.cli_extensions(command) if (e["kind"], e["name"]) not in seen]
    except Exception:
        pass
    return out


def command_is_relevant(command: str, agent=None) -> bool:
    """Should a guard failure on this command be surfaced (instead of silently passing)?"""
    return bool(_INSTALLISH.search(command)) or command_touches_protected_path(command, agent) or bool(_extensions(command, agent))


def file_is_relevant(file_path: str, agent=None) -> bool:
    """Should a guard failure on this file write be surfaced? Only for the files the guard watches."""
    return bool(file_path) and (file_path_is_mcp_config(file_path, agent) or file_path_is_protected(file_path, agent)
                                or index_config.is_watched_file(file_path))


def _with_decision_id(reason: str, report_data: dict) -> str:
    """Name the decision in the message, so "why?" from one of several parallel agents opens its own record
    (/aegis and `guard_cli.py paths --decision <id>`), not whichever decision happened to be written last."""
    did = report_data.get("decision_id")
    if not did or not reason or did in reason:
        return reason
    return f"{reason}\n(decision id: {did})"


def _ask(project_dir: str, report: dict, popup: str, always_ask: bool = False) -> Decision:
    """A guard event a person should look at (not an install: MCP server / extension, protected path, package index).
    user mode: the approval window with `popup`. auto mode - nobody to ask: a refusal that gives the agent why it was
    stopped, the evidence and the path to harm, so it decides what to do instead (r4.mvp_output.auto_event_reason).
    always_ask: an action on the guard itself (turning it off, changing its files or records). The approval window in
    both modes: once the guard is off nothing checks the agent's next steps, and an agent misled by text it read is
    exactly the case to stop, so the agent never decides this one (an unattended run is refused by the agent)."""
    if always_ask:
        report = {**report, "always_ask": True}
    write_report(project_dir, report)
    if always_ask:
        return Decision(CONFIRM, popup)
    try:
        from mode import get_mode
        if get_mode(project_dir) == "auto":
            from r4.mvp_output import auto_event_reason
            card = auto_event_reason(report)
            if card:
                return Decision(REFUSE, _with_decision_id(card, report))
    except Exception:
        pass                                         # the card could not be built: ask as before
    return Decision(CONFIRM, popup)


def _scan_mcp_servers(servers: list, project_dir: str, agent) -> Decision | None:
    """The packages / scripts the new MCP servers' launch commands would run (mcp_scan.py); None = nothing to scan or the
    scan itself failed (the registration check below still asks about an unknown server)."""
    if not servers or switches.get("AASM_MCP_SCAN", "1") == "0":     # 0: registration check only (offline tests)
        return None
    try:
        import mcp_scan
        return mcp_scan.decide(servers, project_dir, agent)
    except Exception:
        return None


def _scan_plugins(specs: list, project_dir: str, agent, agent_name: str) -> Decision | None:
    """The plugins' files and MCP servers (plugin_scan.py); None = nothing to scan or the scan itself failed."""
    if not specs or switches.get("AASM_MCP_SCAN", "1") == "0":     # the same switch: registration checks only
        return None
    try:
        import plugin_scan
        return plugin_scan.decide(specs, project_dir, agent, agent_name)
    except Exception:
        return None


def _scan_config_write(file_path: str, proposed_text, servers: list, project_dir: str, agent) -> Decision | None:
    """One install decision over what a config write adds to an agent: the new MCP servers' launch commands
    (mcp_scan), new hook commands or hook scripts (hook_scan), plugins switched on (plugin_scan). None = nothing added,
    scanning off (AASM_MCP_SCAN=0) or the scan itself failed (the checks after it still ask)."""
    if switches.get("AASM_MCP_SCAN", "1") == "0":
        return None
    try:
        import tempfile
        import hook_scan
        import mcp_scan
        import plugin_scan
        from install_parse import Parsed
        parsed, found = Parsed(), False
        with tempfile.TemporaryDirectory() as tmp:
            parts = [mcp_scan.parsed_for(servers, project_dir) if servers else None]
            if proposed_text is not None:
                parts += [hook_scan.parsed_for_write(file_path, proposed_text, project_dir),
                          plugin_scan.parsed_for_enabled(file_path, proposed_text, Path(tmp))]
            for p in parts:
                if p is not None:
                    parsed.merge(p)
                    found = True
            return check_parsed(parsed, f"extension settings change: {Path(file_path).name}", project_dir, agent) if found else None
    except Exception:
        return None


def _mcp_code_checked(scanned: "Decision | None", launch: str | None) -> bool:
    """True when the server's local code was scanned and passed (the popup must not say "not scanned" then)."""
    try:
        import mcp_scan
        return scanned is not None and scanned.action == ALLOW and mcp_scan.scannable(launch)
    except Exception:
        return False






CHECKS_BUDGET_SECONDS = 540     # one budget for all the checks of a command; the hook's own deadline (570 s) is above it


def _file(rec: dict, verdict: str, records: list, blocked: list, review: list) -> None:
    records.append(rec)
    if verdict == "BLOCK":
        blocked.append(rec)
    elif verdict == "NEEDS_HUMAN_REVIEW":
        review.append(rec)


def _repair_commands() -> list[str]:
    cli = Path(__file__).resolve().parent / "guard_cli.py"
    return [f"python3 -I {cli} verify", f"python3 -I {cli} repair --yes"]


def _index_provenance(parsed) -> None:
    """Indexes the agent adds are recorded; indexes the person set up are not flagged (index_trust.py). Never raises:
    on any failure every unscanned index stays as it was."""
    try:
        import index_trust
        for u in parsed.unscanned:
            if u.get("kind") == "index_setting":
                index_trust.record_agent_change(index_trust.urls_in(u.get("text", "")) or None)
        parsed.unscanned, parsed.trusted_indexes = index_trust.filter_unscanned(parsed.unscanned)
    except Exception:
        pass


def _auto(project_dir) -> bool:
    try:
        from mode import get_mode
        return get_mode(project_dir) == "auto"
    except Exception:
        return False


def _agent_decides(decision: Decision, fp: str) -> Decision:
    """auto mode: a refusal carries the evidence and an ack id; once the agent has run `guard_cli.py ack <id>`, the same
    action passes (acks.py). Every refusal - BLOCK, REVIEW, extension, setting, guard file - is the agent's to decide;
    user mode is unchanged (a person answers). Any failure here leaves the refusal as it was."""
    if decision.action != REFUSE:
        return decision
    try:
        import acks
        if acks.consume(fp):
            return Decision(ALLOW)
        ack_id = acks.issue(fp, decision.reason.splitlines()[0] if decision.reason else "")
        from r4.mvp_output import ack_instruction
        cli = Path(__file__).resolve().parent / "guard_cli.py"
        return Decision(REFUSE, decision.reason + "\n" + ack_instruction(ack_id, f"python3 -I {cli} ack {ack_id}"),
                        decision.detail)
    except Exception:
        return decision


def check_command(command: str, project_dir: str, agent=None, actor: dict | None = None) -> Decision:
    """actor = who ran the command, from the hook event ({"session_id", "agent_id"}); kept in the decision record."""
    decision = _check_command(command, project_dir, agent, actor)
    if decision.action == REFUSE and _auto(project_dir):
        import acks
        return _agent_decides(decision, acks.fingerprint("command", project_dir, command))
    return decision


def check_file_write(file_path: str, proposed_text: str | None, project_dir: str, agent=None) -> Decision:
    """A file is about to be written with `proposed_text` (None = could not be derived)."""
    decision = _check_file_write(file_path, proposed_text, project_dir, agent)
    if decision.action == REFUSE and _auto(project_dir):
        import acks
        return _agent_decides(decision, acks.fingerprint("file", project_dir, file_path, proposed_text))
    return decision


def _check_command(command: str, project_dir: str, agent=None, actor: dict | None = None) -> Decision:
    # A command that writes to a protected guard path is the higher-priority finding - check it before deciding
    # whether this is even an install command at all.
    if command_touches_protected_path(command, agent) or command_changes_guard_install(command):
        shown = clean(command, 90)
        reason = _text_or(
            "popup_protected_path",
            f"{PREFIX} Command modifies a guard-protected path (settings/hooks): {shown} → the safety net could be turned off or tampered with. Details: /aegis", shown)
        return _ask(project_dir, {
            "kind": "protected_path", "verdict": "NEEDS_HUMAN_REVIEW", "command": clean(command, 300),
            "path": "shell command run by the agent → modifies the guard's settings/hook files",
            "risk": "the safety net could be turned off or tampered with",
            "reason": "command pattern that writes to a protected path (agent settings, hooks, guard files)",
            "benign_cases": "legitimate maintenance of the guard by its developer",
        }, reason, always_ask=True)

    # Through the shell: an MCP server / plugin / marketplace added with the agent's own CLI (the Edit/Write hook
    # covers only config files written directly)
    try:
        ext = _extensions(command, agent)
    except Exception:
        ext = []
    if ext:
        is_known = getattr(agent, "extension_is_known", None) if agent is not None else None
        if is_known is None:
            from adapters import DEFAULT as _a
            is_known = getattr(_a, "extension_is_known", lambda e: False)
        scanned = _scan_mcp_servers([{"name": e["name"], "launch": e.get("source")} for e in ext if e["kind"] == "mcp_server"],
                                    project_dir, agent)
        if scanned is not None and scanned.action != ALLOW:
            return scanned
        from adapters import DEFAULT as _default
        plugins = _scan_plugins([e["name"] for e in ext if e["kind"] == "plugin"], project_dir, agent, (agent or _default).NAME)
        if plugins is not None and plugins.action != ALLOW:
            return plugins
        unknown = [e for e in ext if not is_known(e)]
        if unknown and _auto(project_dir):
            # auto mode: what the guard could check and found clean goes on - an MCP server whose code was scanned, a
            # plugin that was scanned, a marketplace (a catalogue: its plugins are scanned when one is installed). Only
            # what could not be checked (a remote server, a plugin the scan could not reach) goes to the agent's decision.
            cleared = lambda e: (e["kind"] == "marketplace" or (e["kind"] == "plugin" and plugins is not None)  # noqa: E731
                                 or (e["kind"] == "mcp_server" and _mcp_code_checked(scanned, e.get("source"))))
            unknown = [e for e in unknown if not cleared(e)]
        if unknown:
            kinds = {"mcp_server": "MCP server", "plugin": "plugin", "marketplace": "plugin marketplace"}
            first = unknown[0]
            names = ", ".join(clean(e["name"], 30) for e in unknown[:3]) + (f" +{len(unknown) - 3} more" if len(unknown) > 3 else "")
            report = {
                "kind": "mcp_server" if first["kind"] == "mcp_server" else "extension", "verdict": "NEEDS_HUMAN_REVIEW",
                "command": clean(command, 300), "code_checked": _mcp_code_checked(scanned, first.get("source")),
                "servers": [{"name": clean(e["name"], 80), "source": clean(e["source"], 200), "kind": e["kind"]} for e in unknown],
                "path": "agent registers an extension with its CLI → new tools/code are connected to the agent",
                "risk": "unverified tools, servers or plugins could be connected to the agent",
                "reason": "command registers an extension that is not on the trusted list",
                "benign_cases": "MCP servers or plugins you wrote yourself or use in-house",
            }
            if first["kind"] == "mcp_server":
                reason = _text_or("popup_mcp", cap_line(f"{PREFIX} Untrusted MCP server registered: {names} ({clean(first['source'], 60)}) "
                                                         "→ unverified tools could be connected to the agent. Details: /aegis"),
                                  names, clean(first["source"], 60), clean(first.get("via") or "CLI", 40),
                                  _mcp_code_checked(scanned, first.get("source")))
            else:
                reason = cap_line(f"{PREFIX} Untrusted {kinds[first['kind']]} added: {names} "
                                  "→ unverified code, hooks or tools could be connected to the agent. Approving adds it. Details: /aegis")
            return _ask(project_dir, report, reason)

    parsed = parse_install_command(command, project_dir, env=dict(os.environ))
    return check_parsed(parsed, command, project_dir, agent, actor)


def check_parsed(parsed, command: str, project_dir: str, agent=None, actor: dict | None = None) -> Decision:
    """The install decision for what a command (or anything that fetches and runs code - an MCP server's launch
    command, a plugin, a hook script) would bring in, already parsed (install_parse.Parsed). `command` is what the
    records and messages show."""
    _index_provenance(parsed)
    if parsed.unscanned and not (parsed.installs or parsed.project_installs) and _auto(project_dir):
        # auto mode: changing where packages come from (`pip config set global.index-url ...`) installs nothing; the
        # installs that later use that index are the ones checked (index_config.findings). In the same command as an
        # install it stays: that install would come from the new index while the scan read PyPI.
        parsed.unscanned = [u for u in parsed.unscanned if u.get("kind") != "index_setting"]
    import checks
    if not checks.wanted(parsed):
        return Decision(ALLOW)   # nothing for any check: not an install command (or only local project folders)

    # The detection rules come from guard/rules/*.json (rule_engine). A broken or tampered rule file must never become
    # a silent pass. Loading here, before the scan threads start, also keeps two threads from importing a failing
    # module at once (that surfaced as a misleading AttributeError instead of the rule-file message).
    try:
        import scan_engine  # noqa: F401
    except Exception as e:
        return _ask(project_dir, {"kind": "rules_error", "verdict": "NEEDS_HUMAN_REVIEW", "command": clean(command, 300),
                                  "reason": "the guard could not check the install because of a rule file error", "error": clean(str(e), 200),
                                  "commands": _repair_commands()},
                    cap_line(f"{PREFIX} Could not check the install because of a rule file error: {clean(str(e), 160)} "
                             "→ check it yourself before allowing. Details: /aegis"))

    # The environment Profile (for attack paths) is collected while the packages are scanned; it never decides anything
    # and a slow or failing Profile is simply skipped.
    profile_box: dict = {}
    profile_thread = None
    try:
        import threading
        from env_profile import collect_cached

        def _collect():
            try:
                profile_box["doc"] = collect_cached(project_dir, agent)
            except Exception as e:
                profile_box["error"] = type(e).__name__
        profile_thread = threading.Thread(target=_collect, daemon=True)
        profile_thread.start()
    except Exception:
        profile_thread = None

    # Every kind of source is checked by its own module (guard/checks/), side by side under one budget; this function
    # only decides on the records they return.
    import time as _time
    ctx = checks.Context(parsed, project_dir, lambda items: scan_packages(items), _time.monotonic() + CHECKS_BUDGET_SECONDS)
    blocked, review, records, extra_report = [], [], [], {}
    outcomes = checks.run_all(ctx)
    for _, out in outcomes:
        for rec, verdict in out.records:
            _file(rec, verdict, records, blocked, review)
    for name, out in outcomes:
        for rec, verdict in out.dependencies:
            _file(rec, verdict, records, blocked, review)
        for key, val in out.report.items():
            if isinstance(val, list):
                extra_report.setdefault(key, []).extend(val)
            else:
                extra_report[key] = val

    # This install checkpoint doubles as the integrity checkpoint - compare the guard's own files against their
    # manifest every time.
    integrity_findings = check_integrity()

    overall = "BLOCK" if blocked else "NEEDS_HUMAN_REVIEW" if (review or integrity_findings) else "ALLOW"
    # detail record for "why?" follow-ups; written on every install decision, ALLOW included, so the
    # file always matches the last one.
    try:                    # which surface (terminal / app / api) this runs on; never allowed to break the gate
        if agent is None:
            from adapters import DEFAULT as agent
        surface = agent.detect_surface()
    except Exception:
        surface = {"surface": "unknown", "width": 60}
    try:
        from mode import get_mode
        mode = get_mode(project_dir)
    except Exception:
        mode = "user"
    report_data = {
        "kind": "install",
        "surface": surface,
        "mode": mode,
        "verdict": overall,
        "command": clean(command, 300),
        "packages": records,
        "integrity_findings": [clean(x, 200) for x in integrity_findings],
    }
    if actor:
        report_data["actor"] = {k: clean(str(v), 80) for k, v in actor.items() if v}
    if getattr(parsed, "project_installs", None):     # scope: direct dependencies, lock versions
        report_data["project_install"] = {"dirs": [clean(d, 200) for d in parsed.project_installs[:5]],
                                          "scope": "direct dependencies from project files checked (lock versions applied). Transitive dependencies: latest versions and known malware only"}
    report_data.update(extra_report)          # what checks add of their own: transitive, npm_dependency_scripts, ...

    write_report(project_dir, report_data)
    if blocked or review:
        _attack_paths(project_dir, report_data, profile_thread, profile_box)

    if blocked:
        # The Markdown report and the fixed-format terminal view (r4.mvp_output) are extras. They are imported HERE and
        # wrapped on purpose: a module-level import error exits 1, and exit 1 does not block - the install would run
        # (in testing, with r4/ missing, `pip install pyyaml==5.3.1` went through). Whatever fails in the
        # extras, the refusal is still sent; if the short message cannot be built we send the full reason instead.
        reason, detail = deny_block(blocked), ""
        try:
            from r4.mvp_output import auto_reason, claude_reason, terminal_report, write_md_report
            try:
                report_path = write_md_report(project_dir, report_data, force=False)
            except Exception:
                report_path = None
            shown_path = None
            if report_path is not None:
                try:
                    shown_path = report_path.relative_to(Path(project_dir))
                except ValueError:
                    shown_path = report_path
            report = terminal_report(report_data, width=surface.get("width"), report_path=shown_path)
            if mode == "auto":
                # auto mode: the reasons stay in the record and the md report; the person gets one line (relayed by
                # the agent), the agent gets the instruction. user mode: the fixed-format report is shown.
                reason = auto_reason(blocked[0], blocked[1:] + review)   # review: same-command packages the card must not hide
            else:
                detail = report
                try:
                    from r4.mvp_output import fix_offers
                    offers = fix_offers(blocked + review)
                except Exception:
                    offers = []
                reason = claude_reason(report, offers)   # user mode: show the report, offer the fixed version, wait
        except Exception:
            pass
        return Decision(REFUSE, _with_decision_id(reason, report_data), detail)

    if review or integrity_findings:
        if integrity_findings and mode == "auto":
            # auto mode: nobody to ask - the agent is told the guard cannot be trusted right now and installs nothing
            try:
                from r4.mvp_output import auto_event_reason
                card = auto_event_reason({"kind": "integrity", "reason": "guard files differ from the installed version",
                                          "integrity_findings": integrity_findings,
                                          "commands": _repair_commands()})
            except Exception:
                card = None
            if card:
                return Decision(REFUSE, _with_decision_id(card, report_data))
        if integrity_findings:
            # the guard's own tampering outranks a package finding; both are in the report
            extra = f" (also {len(review)} package review(s))" if review else ""
            reason = _text_or(
                "popup_integrity",
                f"{PREFIX} Guard file integrity problem: {clean(integrity_findings[0], 80)}{extra} → possible tampering with the guard. Details: /aegis",
                clean(integrity_findings[0], 80), len(review))
        elif mode == "auto":
            # auto mode = no person in the loop: nothing is asked. The REVIEW is handed to the agent as a card with the
            # steps to resolve it (same channel and instruction as a BLOCK); the agent's next install is checked again.
            try:
                from r4.mvp_output import auto_reason
                card = auto_reason(review[0], review[1:])
            except Exception:
                card = None
            if card:
                return Decision(REFUSE, _with_decision_id(card, report_data))
            reason = one_liner(review[0], extra_packages=len(review) - 1)   # the card could not be built: ask the person as before
        else:
            reason = _text_or("popup_line", one_liner(review[0], extra_packages=len(review) - 1), review[0], len(review) - 1)
        return Decision(CONFIRM, _with_decision_id(reason, report_data))

    return Decision(ALLOW)


PROFILE_WAIT_SECONDS = 5.0


def _attack_paths(project_dir, record: dict, thread, box: dict) -> None:
    """Rule-only attack paths for this decision -> .aasm/attack_paths/<decision_id>.json (+ attack_paths.json, latest).
    No AI here: CVE judgements are only asked for when the user requests paths (guard_cli.py paths --judge)."""
    try:
        if thread is None:
            return
        thread.join(PROFILE_WAIT_SECONDS)
        if thread.is_alive() or "doc" not in box:
            return                                        # Profile slow or failed: no paths this time, verdict unchanged
        import json as _json
        import attack_path
        result = attack_path.run(project_dir, profile=box["doc"], record=record)
        result["profile_cache"] = box["doc"].get("cache")
        d = Path(project_dir) / ".aasm" / "attack_paths"
        d.mkdir(parents=True, exist_ok=True)
        text = _json.dumps(result, ensure_ascii=False)
        if record.get("decision_id"):
            (d / f"{record['decision_id']}.json").write_text(text)
        (Path(project_dir) / ".aasm" / "attack_paths.json").write_text(text)
    except Exception:
        pass


def _check_file_write(file_path: str, proposed_text: str | None, project_dir: str, agent=None) -> Decision:
    from mcp_guard import check_new_mcp_servers

    # What the write adds to any agent's extensions (agent_formats.json): new MCP servers' launch commands, new hook
    # commands / hook scripts, plugins switched on - one install decision over all of it.
    is_mcp = file_path_is_mcp_config(file_path, agent)
    protected = file_path_is_protected(file_path, agent)
    # the guard itself (its files, its records, or a settings edit that switches it off): a person decides, in any mode
    if protected and (path_is_guard_own(file_path) or settings_change_disables_guard(file_path, proposed_text)):
        own = path_is_guard_own(file_path)
        return _ask(project_dir, {
            "kind": "protected_path", "verdict": "NEEDS_HUMAN_REVIEW", "file": clean(file_path, 200),
            "path": "agent's file edit tool → " + ("changes the guard's own files or records" if own
                                                   else "edits agent settings so the guard's hooks no longer run"),
            "risk": "the safety net could be turned off or tampered with",
            "reason": "edit of the guard itself" if own else "settings edit that turns the guard off",
            "benign_cases": "you asked the agent to change or remove the guard",
        }, _text_or(
            "popup_protected_path",
            cap_line(f"{PREFIX} Direct edit of a guard-protected path: {clean(file_path, 90)} → the safety net could be turned off or tampered with. Details: /aegis"),
            clean(file_path, 90)), always_ask=True)
    new = check_new_mcp_servers(file_path, proposed_text) if is_mcp else []
    scanned = _scan_config_write(file_path, proposed_text, new, project_dir, agent)
    if scanned is not None and scanned.action != ALLOW:
        return scanned

    # MCP configs get the specific known-vs-unknown server diff. A file that is also a protected agent setting
    # (Codex's config.toml) still goes on to the protected-path check below.
    if is_mcp:
        unknown = [e for e in new if not e["known"]]
        if unknown and _auto(project_dir):       # auto mode: servers whose code was scanned clean go on (see _check_command)
            unknown = [e for e in unknown if not _mcp_code_checked(scanned, e.get("launch"))]
        if not unknown and not protected:
            return Decision(ALLOW)   # known entries, or no new entries at all
    if is_mcp and unknown:
        names = ", ".join(clean(e["name"], 30) for e in unknown[:3]) + (f" +{len(unknown) - 3} more" if len(unknown) > 3 else "")
        checked = _mcp_code_checked(scanned, unknown[0].get("launch"))
        return _ask(project_dir, {
            "kind": "mcp_server", "verdict": "NEEDS_HUMAN_REVIEW", "file": clean(file_path, 200), "code_checked": checked,
            "servers": [{"name": clean(e["name"], 80), "source": clean(e["source"], 200)} for e in unknown],
            "path": "agent edits an MCP config file → a new server is connected as one of the agent's tools",
            "risk": "unverified tools or servers could be connected to the agent",
            "reason": "a new MCP server entry that is not on the trusted list (allowlist) was added",
            "benign_cases": "MCP servers you wrote yourself or use in-house",
        }, _text_or(
            "popup_mcp",
            cap_line(f"{PREFIX} Untrusted MCP server registered: {names} ({clean(unknown[0]['source'], 60)}) "
                     f"in {clean(Path(file_path).name, 30)} → unverified tools could be connected to the agent. Details: /aegis"),
            names, clean(unknown[0]["source"], 60), clean(Path(file_path).name, 30), checked))

    if protected:
        return _ask(project_dir, {
            "kind": "protected_path", "verdict": "NEEDS_HUMAN_REVIEW", "file": clean(file_path, 200),
            "path": "agent's file edit tool → edits the guard's settings/hook files directly",
            "risk": "the safety net could be turned off or tampered with",
            "reason": "direct edit of a protected path (agent settings, hooks, guard files)",
            "benign_cases": "legitimate maintenance of the guard by its developer",
        }, _text_or(
            "popup_protected_path",
            cap_line(f"{PREFIX} Direct edit of a guard-protected path: {clean(file_path, 90)} → the safety net could be turned off or tampered with. Details: /aegis"),
            clean(file_path, 90)))

    # where later installs come from: pip.conf / uv.toml / pyproject.toml / Pipfile written with the file tools
    # (the same write through the shell is caught by install_parse). It also changes the user's own installs
    # outside the agent, which the guard never sees, so it is asked at the write, not only at the next install.
    # The index is recorded as the agent's (index_trust.py): installs from it are cards, the person's own indexes are not.
    # auto mode: the setting itself goes on; the installs that use it are where the agent gets the evidence.
    added = index_config.written_file(file_path, proposed_text)
    if added:
        try:
            import index_trust
            index_trust.record_agent_change([u for _, t, _ in added for u in index_trust.urls_in(t)] or None)
        except Exception:
            pass
    if added and not _auto(project_dir):
        shown = clean(added[0][1], 80) + (f" +{len(added) - 1} more" if len(added) > 1 else "")
        return _ask(project_dir, {
            "kind": "index_config", "verdict": "NEEDS_HUMAN_REVIEW", "file": clean(file_path, 200),
            "sources": [clean(t, 200) for _, t, _ in added[:10]],
            "path": "agent's file edit tool → edits a package config file → later installs download from that address",
            "risk": "packages could be installed from another server instead of the PyPI package the guard checked (including installs outside the agent)",
            "reason": added[0][2],
            "benign_cases": "in-house mirror or private index, local wheel folder",
        }, _text_or(
            "popup_index_config",
            cap_line(f"{PREFIX} Package index setting changed: {shown} → later installs may download from a server the guard did not check. Details: /aegis"),
            shown, clean(Path(file_path).name, 30)))

    return Decision(ALLOW)
