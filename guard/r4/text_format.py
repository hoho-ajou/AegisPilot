"""
AegisPilot - the text a person reads when a package is blocked or needs review .

Three shapes, all plain text for a terminal (no colour, no images):
  summary_line()   A  one line, <= 66 columns  (auto mode: what the person sees)
  popup_*()        C  one sentence, <= 200 characters (the confirmation dialog Claude Code draws for REVIEW)
  report_text()    D  labelled report, <= width columns  (guard_cli report, .aasm/reports, user mode)

Order of labels is fixed: Reason -> Impact -> Evidence -> Fix -> Limits -> Details (Source for sources we cannot read,
Warning for integrity). A label with no value is left out; Limits is always there. ALLOW prints nothing, so there is no ALLOW shape.

Everything that comes from the package or from a file the agent can write goes through _plain (control characters and
invisible characters removed); numbers the guard computed and fixed wording are the rest.
"""
from __future__ import annotations

import re

import review_report as _rr
from r4 import mvp_output as _m

_plain = _m._plain
display_width = _m.display_width
wrap = _m.wrap
LABEL_W = 8                                      # widest label ("Evidence"); shorter labels are padded to it
IND = " " * (LABEL_W + 2)                        # hanging indent: the padded label + 2 spaces
_SAFE_NAME = re.compile(r"^(@[A-Za-z0-9._-]{1,40}/)?[A-Za-z0-9._-]{1,60}$")   # PyPI name, or npm @scope/name
_VER_OK = re.compile(r"^[0-9A-Za-z.!+_-]{1,30}$")
_BLOCK_CODE_RULES = ("pth_chain", "decode_then_exec", "download_then_execute")
_NOT_EVIDENCE = {"osv", "typosquat", "unscanned_source", "fetch_error", "score", "reputation"}

SHORT = {"decode_then_exec": "decode-then-exec code", "download_then_execute": "download-then-run code", "pth_chain": "startup exec chain",
         "pth_exec": "code run at startup", "setup_hidden_shell": "hidden shell at install", "setup_network": "network call at install",
         "install_hook_import": "install hook loads risky module", "install_hook": "install hook", "high_entropy": "obfuscated block",
         "keyword": "uses a dangerous API", "reputation": "weak trust signals", "score": "combined risk signals",
         "new_package": "newly registered package", "policy_deny": "denied by policy", "known_malicious": "known malicious version", "osv_unavailable": "vuln DB lookup failed", "new_risky_code": "new risky code", "late_file": "recently added file"}
LONG = {"decode_then_exec": "decodes code and runs it right away (within 8 lines)", "download_then_execute": "runs code it downloaded (within 8 lines)",
        "pth_chain": "dangerous exec chain in a file that runs every time Python starts", "pth_exec": "dangerous call in a file that runs every time Python starts",
        "setup_hidden_shell": "setup.py runs a hidden shell (powershell etc.)", "setup_network": "setup.py connects to the network during install",
        "install_hook_import": "install hook loads a module with dangerous calls", "install_hook": "has a custom install hook",
        "high_entropy": "has a long encoded block that looks obfuscated", "keyword": "calls a dangerous API", "reputation": "weak trust signals (new, no description, etc.)", "known_malicious": "listed in OSV as a version that shipped malicious code (hijacked or malicious release)", "new_package": "first registered on PyPI less than 30 days ago (squatted made-up name or new malware possible)", "policy_deny": "on the deny list of the organization or project policy", "osv_unavailable": "could not reach OSV (known vulnerability and malicious version DB), so known risks were not checked", "new_risky_code": "code not in the previous version runs commands, network or binaries at import or install (possibly a hijacked release)", "late_file": "an install file was added recently to an old version (a hijacked account slipping a file into an existing release)"}
BASE_LIMIT = "older dependencies are checked against OSV only; native binaries are not scanned"


# ----------------------------------------------------------------------------------------------- facts about one record
def _name(rec: dict) -> str:
    n = str(rec.get("package") or "")
    return n if _SAFE_NAME.match(n) else "(name omitted)"


def _ver(rec: dict) -> str:
    v = str(rec.get("version") or "")
    return v if _VER_OK.match(v) else ""


def _rules(rec: dict) -> list[str]:
    return [str(e.get("rule")) for e in rec.get("evidence") or []]


def _evidence(rec: dict, rule: str) -> dict:
    return next((e for e in rec.get("evidence") or [] if e.get("rule") == rule), {})


def _short(rule: str) -> str:
    return SHORT.get(rule) or _rr.RULES.get(rule, {}).get("label") or "risk signal"


def _long(rule: str) -> str:
    return LONG.get(rule) or _rr.RULES.get(rule, {}).get("reason") or "risk signal"


def case_of(rec: dict) -> str:
    """code | osv | typo | unscanned | fetch | weak - why this package is in front of a person."""
    rules = _rules(rec)
    adv = rec.get("advice") or {}
    if "known_malicious" in rules:
        return "weak"            # its own label leads (_lead_rule); not an OSV fix case
    if any(r in _BLOCK_CODE_RULES or r in _rr.LEAD_FILE_RULES for r in rules):
        return "code"
    if adv.get("vuln_count") or adv.get("ids"):
        return "osv"
    if "typosquat" in rules and adv.get("typosquat_of"):
        return "typo"
    if "unscanned_source" in rules or rec.get("source"):
        return "unscanned"
    if "fetch_error" in rules or (rec.get("coverage") or {}).get("analyzed") is False:
        return "fetch"
    return "weak"


def _lead_rule(rec: dict) -> str:
    rules = _rules(rec)
    if "known_malicious" in rules:
        return "known_malicious"
    for r in (*_BLOCK_CODE_RULES, *_rr.LEAD_FILE_RULES):
        if r in rules:
            return r
    for r in ("known_malicious", "policy_deny", "new_risky_code", "late_file", "osv_unavailable", "new_package", "pth_exec", "setup_hidden_shell", "setup_network", "install_hook_import", "install_hook", "high_entropy", "keyword", "reputation"):
        if r in rules:
            return r
    return "score"


def _worst(rec: dict) -> dict:
    groups = (rec.get("advice") or {}).get("vuln_groups") or []
    return groups[0] if groups else {}


def _severity(rec: dict) -> str:
    adv = rec.get("advice") or {}
    return str(_worst(rec).get("severity") or adv.get("severity") or "")


def _first_id(rec: dict) -> str:
    g = _worst(rec)
    ids = g.get("ids") or (rec.get("advice") or {}).get("ids") or []
    return str(ids[0]) if ids else ""


def _others(rec: dict, lead: str | None = None) -> int:
    """How many other KINDS of signal there are besides the one named (never 'N more vulnerabilities')."""
    rules = {r for r in _rules(rec) if r not in ("osv", "score")}
    if lead:
        rules.discard(lead)
    return len(rules)


def cvss_words(vec: str) -> str:
    """CVSS 3.x vector -> plain words. AV:N -> remote, PR:N -> no login needed, UI:R -> needs a click, C/I/A:H -> big impact.
    The base score is not computed."""
    try:
        m = dict(p.split(":", 1) for p in str(vec).split("/")[1:])
    except ValueError:
        return ""
    where = {"N": "remote (network)", "A": "adjacent network", "L": "local", "P": "physical access"}.get(m.get("AV", ""), "")
    auth = {"N": "no login needed", "L": "low privileges needed", "H": "high privileges needed"}.get(m.get("PR", ""), "")
    ui = "needs user action" if m.get("UI") == "R" else ""
    hit = [n for k, n in (("C", "confidentiality"), ("I", "integrity"), ("A", "availability")) if m.get(k) == "H"]
    impact = ("high " + ", ".join(hit) + " impact") if hit else ""
    return " · ".join(x for x in (where, auth, ui, impact) if x)


# ----------------------------------------------------------------------------------------------- A: one line (<= 60)
def _fit(parts: list[str], width: int, head: str) -> str:
    """head + parts joined by ' · '; drops trailing parts, then cuts, until it fits."""
    parts = [p for p in parts if p]
    while parts:
        line = head + " · ".join(parts)
        if display_width(line) <= width:
            return line
        if len(parts) == 1:
            break
        parts.pop()
    line = head + (parts[0] if parts else "")
    while display_width(line) > width - 1 and len(line) > 10:
        line = line[:-1]
    return line + "…"


def summary_line(rec: dict, width: int = 66) -> str:
    name, ver = _name(rec), _ver(rec)
    case, adv = case_of(rec), rec.get("advice") or {}
    word = "blocked" if str(rec.get("verdict")) == "BLOCK" else "held"             # REVIEW in auto mode is held back, not blocked
    variants: list[list[str]] = []
    if case == "osv":
        sev = _severity(rec)
        tail = f"upgrade to >={adv['fix_version']}" if adv.get("fix_version") else "no fixed version"
        # when it is too long the SEVERITY WORDING shrinks first; the action (what to do) is kept to the end
        variants = [[f"{sev} vulnerability" if sev else "vulnerability", tail], [sev or "vulnerability", tail], [tail]]
        parts = variants[0]
    elif case == "typo":
        parts = [f"name close to '{_plain(adv['typosquat_of'], 40)}'"]
    elif case == "code":
        parts = [_short(_lead_rule(rec))]
    elif case == "fetch":
        kind = adv.get("failure_kind") or (rec.get("coverage") or {}).get("failure_kind") or "other"
        label = _plain((rec.get("coverage") or {}).get("failure") or "scan failed", 20)
        todo = {"not_found": "check the name", "version_missing": "check the version", "too_big": "could not read"}.get(
            kind, "try again" if kind in ("network", "registry", "timeout", "crash") else "not scanned")
        variants = [[label, todo], [label]]
        parts = variants[0]
    elif case == "unscanned" and (rec.get("source") or {}).get("kind") == "too_many_packages":
        name = "some packages"
        variants = [["too many to scan", "split it up"], ["not scanned"]]
        parts = variants[0]
    elif case == "unscanned":
        src = rec.get("source") or {}
        kind = src.get("kind")
        name = _plain(src.get("name") or src.get("repo") or src.get("host") or "", 40) or {
            "find_links": "local path", "unparsed": "unparsed command", "requirements_unreadable": "requirements file"}.get(kind, "external source")
        what = {"vcs_or_url": "git source" if src.get("repo") or "git+" in str(rec.get("package") or "") else "URL source",
                "custom_index": "private index", "index_setting": "index setting", "find_links": "find-links"}.get(kind, "not scanned")
        todo = "use the PyPI version" if kind in ("vcs_or_url", "find_links") else "not scanned"
        variants = [[what, todo] if what != todo else [what], [todo]]
        parts = variants[0]
    else:
        parts = [_short(_lead_rule(rec))]
    # the verdict word (blocked/held) is the last thing to lose: shorten the name, then drop the version, then the reasons
    for keep_ver in (True, False):
        n = name
        while True:
            ident = f"[AegisPilot] {n}" + (f" {ver}" if ver and keep_ver else "") + f" {word}"
            if display_width(ident + " · " + parts[0]) <= width or len(n) <= 12:
                break
            n = n[: max(12, len(n) - 4)].rstrip("-._") + "…" if not n.endswith("…") else n[:-2] + "…"
        if display_width(ident) <= width:
            for v in variants or [parts]:
                if display_width(ident + " · " + " · ".join(v)) <= width:
                    return ident + " · " + " · ".join(v)
            if not variants:
                return _fit(parts, width, ident + " · ")                # no variants: cut the parts as before
    return ident[: max(10, width - 1)] + "…"


# ----------------------------------------------------------------------------------------------- C: confirmation dialog
def _cap(line: str) -> str:
    return _rr.cap_line(_plain(line, 400))


def popup_line(rec: dict, extra_packages: int = 0) -> str:
    name, ver = _name(rec), _ver(rec)
    case, adv = case_of(rec), rec.get("advice") or {}
    who = f"{name}" + (f" {ver}" if ver else "") + (f" and {extra_packages} more packages" if extra_packages else "")
    if rec.get("via"):                                   # a dependency the command pulls in, not a package it names
        who += f" (dependency of: {_plain(rec['via'], 60)})"
    tail = " Details: /aegis"
    if case == "unscanned":
        src = rec.get("source") or {}
        text = _plain(rec.get("package") or "", 60)
        kind = src.get("kind")
        if kind == "custom_index":
            body = f"installs from private index{(' ' + src['host']) if src.get('host') else ''}; it may be different code under a PyPI name. If approved, it installs as is."
        elif kind == "find_links":
            body = f"installs from a given path (find-links); the code was not scanned. If approved, it installs unscanned."
        elif kind in ("unparsed", "requirements_unreadable"):
            body = "could not tell what gets installed (variables, substitution, unreadable file). If approved, it runs as is."
        elif kind == "too_many_packages":
            body = "too many packages in one install, so some were not scanned. Install them in smaller batches. If approved, the rest install unscanned."
        else:
            body = "source outside PyPI, so the code was not scanned. If approved, it installs unscanned."
        return _cap(f"{_rr.PREFIX} {text} — {body}{tail}")
    if case == "osv":
        n = adv.get("vuln_count") or len(adv.get("ids") or []) or 1
        sev, first = _severity(rec), _first_id(rec)
        what = f"{n} {sev + ' ' if sev else ''}{'vulnerability' if n == 1 else 'vulnerabilities'}" + (f" ({first} and others)" if n > 1 and first else f" ({first})" if first else "")
        fix = f" → {adv['fix_version']} or later recommended" if adv.get("fix_version") else " → no fixed version"
        other = _others(rec)
        extra = f", {other} other signal kind(s)" if other else ""
        return _cap(f"{_rr.PREFIX} {who} — {what}{fix}{extra}. If approved, it installs as is.{tail}")
    if case == "typo":
        return _cap(f"{_rr.PREFIX} {who} — name is close to the popular package '{_plain(adv['typosquat_of'], 40)}'. Check it is not a typo. If approved, it installs as is.{tail}")
    if case == "fetch":
        kind = (rec.get("advice") or {}).get("failure_kind") or (rec.get("coverage") or {}).get("failure_kind") or "other"
        why = _plain((rec.get("coverage") or {}).get("failure") or _evidence(rec, "fetch_error").get("snippet") or "unknown cause", 40)
        reg = _rr.REGISTRY_NAMES.get(rec.get("ecosystem") or "pypi", "PyPI")
        if kind == "not_found":
            return _cap(f"{_rr.PREFIX} {who} — name not on {reg}. It may be a typo or a made-up name. If approved, it tries to install unscanned.{tail}")
        if kind == "version_missing":
            return _cap(f"{_rr.PREFIX} {who} — version not on {reg}. Check the version. If approved, it tries to install unscanned.{tail}")
        if kind == "too_big":
            return _cap(f"{_rr.PREFIX} {who} — package too big, the code was not read. If approved, it installs unscanned.{tail}")
        if kind in ("network", "registry", "timeout", "crash"):
            return _cap(f"{_rr.PREFIX} {who} — not scanned: {why} (may be temporary). Try again. If approved, it installs unscanned.{tail}")
        return _cap(f"{_rr.PREFIX} {who} — scan failed ({why}). If approved, it installs unscanned.{tail}")
    lead = _lead_rule(rec)
    loc = _plain(_evidence(rec, lead).get("location") or "", 50)
    more = _others(rec, lead)
    extra = f", {more} other signal kind(s)" if more else ""
    return _cap(f"{_rr.PREFIX} {who} — {_short(lead)}{f' ({loc})' if loc else ''}{extra}. If approved, it installs as is.{tail}")


def _path(value: object, limit: int = 60) -> str:
    """A file path for a one-line message: shortened from the left, so the file name - the part that says what changes -
    is what stays."""
    s = _plain(value, 1000)
    if len(s) <= limit:
        return s
    if " " in s:                                     # a shell command (the shell branch passes one): its start says what it does
        return s[: limit - 1] + "…"
    return "…" + s[-(limit - 1):]


def popup_protected_path(file_path: str) -> str:
    return _cap(f"{_rr.PREFIX} Guard setting change: {_path(file_path)} — the safety net may be turned off or changed. If approved, the change is made. Details: /aegis")


def popup_mcp(names: str, source: str, file_name: str, code_checked: bool = False) -> str:
    """code_checked: the server's package / script was scanned and nothing was found (mcp_scan.py); a remote server or a
    container cannot be scanned."""
    checked = "code scanned, nothing found" if code_checked else "code not scanned"
    return _cap(f"{_rr.PREFIX} MCP server '{_plain(names, 50)}' added ({_plain(source, 60)}, {_plain(file_name, 30)}) — new server, {checked}. "
                "If approved, the agent can use this server's tools. Details: /aegis")


def popup_integrity(finding: str, extra_review: int = 0) -> str:
    more = f" ({extra_review} package review(s) separately)" if extra_review else ""
    return _cap(f"{_rr.PREFIX} Guard files seem changed: {_plain(finding, 80)}{more} — possible tampering with the safety net. If approved, it goes ahead as is. Details: /aegis")


# ----------------------------------------------------------------------------------------------- D: labelled report
def _rows_osv(rec: dict) -> list[tuple[str, str]]:
    adv = rec.get("advice") or {}
    groups = adv.get("vuln_groups") or []
    n = adv.get("vuln_count") or len(groups) or 1
    sev = _severity(rec)
    rows: list[tuple[str, str]] = []
    if n == 1 and groups:
        g = groups[0]
        ids = g.get("ids") or []
        main = ids[0] if ids else ""
        alias = ", ".join(x for x in [ids[1] if len(ids) > 1 else "", g.get("cwe", "")] if x)
        rows.append(("Reason", f"1 {sev + ' ' if sev else ''}vulnerability {main}" + (f" ({alias})" if alias else "")))
    else:
        rows.append(("Reason", f"{n} {sev + ' ' if sev else ''}vulnerabilities (aliases of one vulnerability counted once)"))
        for g in groups[:3]:
            ids = g.get("ids") or []
            if ids:
                rows.append(("", ids[0] + (f" ({ids[1]})" if len(ids) > 1 and ids[1].startswith("CVE") else "")))
        if n > 3:
            rows.append(("", f"{n - 3} more"))
    words = cvss_words(_worst(rec).get("cvss", ""))
    rows.append(("Impact", words or _rr.RULES["osv"]["risk"]))
    return rows


def build_rows(rec: dict, report_path: str | None) -> tuple[str, list[tuple[str, str]]]:
    """(head, [(label, text)]) for one package record."""
    name, ver = _name(rec), _ver(rec)
    verdict = str(rec.get("verdict") or "")
    word = "BLOCK" if verdict == "BLOCK" else "REVIEW"
    case, adv = case_of(rec), rec.get("advice") or {}
    head = f"[AegisPilot {word}] " + (_plain(rec.get("package") or "", 70) if case == "unscanned" else f"{name}" + (f" {ver}" if ver else ""))
    rows: list[tuple[str, str]] = []
    if rec.get("via"):
        rows.append(("Path", f"{_plain(rec['via'], 120)} (a dependency pulled in by the package being installed)"))
    lead = _lead_rule(rec)
    if case == "unscanned":
        src = rec.get("source") or {}
        rows.append(("Reason", "too many packages in one command, so some were not scanned" if src.get("kind") == "too_many_packages"
                    else "a source whose code cannot be fetched and scanned (outside PyPI, variables, substitution, unreadable file, etc.)"))
        if src.get("repo"):
            rows.append(("Source", f"{src.get('host', '')} / {src['repo']} " + ("(pinned to a commit)" if src.get("pinned") else "(branch or tag, not pinned to a commit)")))
        elif src.get("host"):
            rows.append(("Source", f"{src['host']} (an index other than PyPI)"))
        rows.append(("Impact", _rr.RULES["unscanned_source"]["risk"]))
        rows.append(("Fix", "approve if you trust the source, otherwise install the PyPI version"))
        rows.append(("Limits", "no code from this source was read"))
    elif case == "osv":
        rows += _rows_osv(rec)
        code = [r for r in _rules(rec) if r in _BLOCK_CODE_RULES]
        if code:
            rows.insert(1, ("", "+ " + LONG[code[0]]))
    elif case == "code":
        rows.append(("Reason", _long(lead)))
        rows.append(("Impact", _rr.RULES.get(lead, {}).get("risk", "")))
        if adv.get("vuln_count"):
            rows.append(("", f"+ {adv['vuln_count']} {_severity(rec) + ' ' if _severity(rec) else ''}vulnerabilities {_first_id(rec)}".rstrip()))
    elif case == "typo":
        rows.append(("Reason", f"name is close to the popular package '{_plain(adv['typosquat_of'], 40)}'"))
        rows.append(("Impact", _rr.RULES["typosquat"]["risk"]))
    elif case == "fetch":
        why = _plain((rec.get("coverage") or {}).get("failure") or _evidence(rec, "fetch_error").get("snippet") or "unknown cause", 100)
        rows.append(("Reason", f"not scanned: {why}"))
    else:
        labels = [e.get("label") for e in rec.get("evidence") or [] if e.get("rule") not in ("score",)][:4]
        rows.append(("Reason", "several weak risk signals: " + ", ".join(_plain(l, 20) for l in labels if l) if labels else _long(lead)))
        if _rr.RULES.get(lead, {}).get("risk"):
            rows.append(("Impact", _rr.RULES[lead]["risk"]))
    if case != "unscanned":
        ev = [e for e in rec.get("evidence") or [] if e.get("rule") not in _NOT_EVIDENCE][:4]
        for i, e in enumerate(ev):
            loc, lab = _plain(e.get("location") or "", 70), _plain(e.get("label") or e.get("rule") or "", 30)
            rows.append(("Evidence" if i == 0 else "", f"{loc} {lab}".strip()))
        # action
        if case == "osv" and not any(r in _BLOCK_CODE_RULES for r in _rules(rec)):
            if adv.get("fix_version"):
                multi = (adv.get("vuln_count") or 1) > 1
                rows.append(("Fix", f"upgrade to {name}>={adv['fix_version']} ({'per OSV, the lowest version that fixes all' if multi else 'OSV fixed version'})"))
            else:
                rows.append(("Fix", "no fixed version: do not install"))
        elif case in ("code", "osv"):
            rows.append(("Fix", "do not install. The user picks any replacement package"))
        elif case == "typo":
            rows.append(("Fix", f"check whether you meant '{_plain(adv['typosquat_of'], 40)}'"))
        elif case == "fetch":
            fk = (adv.get("failure_kind") or (rec.get("coverage") or {}).get("failure_kind") or "other")
            rows.append(("Fix", {
                "not_found": "find the real package name on PyPI and fix it in the requirements file (approve if it is on a private index)",
                "version_missing": "change to a version that exists on PyPI",
                "too_big": "approve only if the package is really needed (the code was not read)",
                "network": "try again in a moment", "registry": "try again in a moment",
                "timeout": "try again in a moment", "crash": "try again; if it keeps failing, check the guard log",
            }.get(fk, "approve only if you trust the package")))
        else:
            rows.append(("Fix", "check that the package is needed; if not, do not install it"))
        # limits
        cov = rec.get("coverage") or {}
        if cov.get("analyzed") is False or case == "fetch":
            rows.append(("Limits", "this package was not scanned (not read)"))
        else:
            rows.append(("Limits", "static analysis: it cannot prove the code is malicious" if case == "code" else BASE_LIMIT))
        for note in cov.get("notes") or []:
            rows.append(("", _plain(note, 80)))
    if report_path:
        rows.append(("Details", _plain(report_path, 200)))
    return head, [(l, _plain(t, 400)) for l, t in rows if t]


def rows_to_lines(rows: list[tuple[str, str]], width: int) -> list[str]:
    out: list[str] = []
    for label, text in rows:
        first = f"{label:<{LABEL_W}}  " if label else IND
        if label == "Details" and display_width(first + text) > width:   # a path never breaks: it goes on its own line
            out += [label, "  " + text]
        else:
            out += wrap(first, text, IND, width)
    return out


def _event_rows(report: dict, report_path: str | None) -> tuple[str, list[tuple[str, str]]] | None:
    kind = report.get("kind")
    if kind == "protected_path":
        rows = [("Reason", f"about to change a guard setting or hook file: {_plain(report.get('file') or '', 120)}"),
                ("Impact", "the safety net may be turned off or changed"), ("Fix", "approve only if you meant to make this change"),
                ("Limits", "it cannot show what changes or how")]
        head = "[AegisPilot REVIEW] guard setting change"
    elif kind == "mcp_server":
        servers = report.get("servers") or []
        names = ", ".join(_plain(s.get("name"), 30) for s in servers[:3])
        rows = [("Reason", "a new MCP server not on the trusted list is being added")]
        if servers:
            rows.append(("Source", _plain(servers[0].get("source") or "", 120)))
        rows += [("Impact", "the agent can use this server's tools"), ("Fix", "approve only if you added it or know the server"),
                 ("Limits", "the server code and tool descriptions are not scanned")]
        head = f"[AegisPilot REVIEW] MCP server added {names}".rstrip()
    elif kind == "index_config":
        sources = report.get("sources") or []
        rows = [("Reason", _plain(report.get("reason") or "a package index other than PyPI was added to a package config file", 120))]
        rows += [("Source", _plain(s, 120)) for s in sources[:3]]
        rows += [("Impact", "later installs (also outside the agent) may download from a server the guard does not check"),
                 ("Fix", "approve only if you know the address, such as an internal mirror"),
                 ("Limits", "packages served by that server are not scanned")]
        head = f"[AegisPilot REVIEW] package index change {_plain(str(report.get('file') or '').rsplit('/', 1)[-1], 30)}".rstrip()
    else:
        return None
    if report_path:
        rows.append(("Details", _plain(report_path, 200)))
    return head, rows


def _integrity_rows(findings: list) -> list[tuple[str, str]]:
    names = []
    for f in findings:
        m = re.match(r"^([A-Za-z0-9_./-]{1,60}) ", str(f))
        names.append(m.group(1) if m else _plain(f, 40))
    return [("Warning", f"{len(findings)} guard file(s) differ from the record: " + ", ".join(names[:3]) + (" and more" if len(names) > 3 else "")),
            ("", "possible tampering with the safety net (restore it unless you changed it yourself)")]


def report_text(report: dict, width: int | None = None, report_path: str | None = None) -> str:
    width = max(30, min(120, int(width))) if width else _m.REPORT_WIDTH
    ev = _event_rows(report, report_path)
    if ev:
        head, rows = ev
    else:
        pkgs = report.get("packages") or []
        pkg = _m.primary_package(report)
        head, rows = build_rows(pkg, report_path)
        others = [p for p in pkgs if p is not pkg and p.get("verdict") != "ALLOW"]
        if others:
            # name the other packages (a bare "and N more" left the reader, and the agent relaying it, unable to say which)
            named = [f"{_name(p)}" + (f" {_ver(p)}" if _ver(p) else "") for p in others[:3]]
            head += " and " + ", ".join(named) + (" …" if len(others) > 3 else "")
            extra = [("Also", _plain(summary_line(p), 70).replace("[AegisPilot] ", "", 1)) for p in others[:3]]
            rows = (rows[:-1] if rows and rows[-1][0] == "Details" else rows) + extra + (rows[-1:] if rows and rows[-1][0] == "Details" else [])
    findings = report.get("integrity_findings") or []
    if findings:
        rows = (rows[:-1] if rows and rows[-1][0] == "Details" else rows) + _integrity_rows(findings) + (rows[-1:] if rows and rows[-1][0] == "Details" else [])
    head = _plain(head, 200)
    while display_width(head) > width and len(head) > 12:          # the first line obeys the width too (a long URL, a long name)
        head = head[: max(12, len(head) - 4)].rstrip() if not head.endswith("…") else head[:-2] + "…"
        if not head.endswith("…"):
            head += "…"
    return "\n".join([head] + rows_to_lines(rows, width))
