"""
AegisPilot - attack paths: from a package the guard flagged to the assets it could reach in this environment.

  package -> finding -> capability -> [code location] -> principal -> asset [-> impact]

Inputs: the guard record (.aegis/last_review.json), the environment Profile (env_profile.collect: principals, assets,
MCP servers, the code under development) and, optionally, AI judgements about CVEs (.aegis-ai/cve_judgments.json).
Everything is decided by rules except one question: "does this CVE's attack condition hold in our code?". That answer
comes from the user's agent (cve_judgement_request()), is accepted only when every quoted piece of evidence really is in
the cited file, and only ever reads trusted text: the OSV advisory, the user's own code, and fixed values from the guard
record - never the package's code or description (an attacker writes those).

Paths are explanation, not a verdict: nothing here changes ALLOW / REVIEW / BLOCK.

Confidence: "confirmed" when every edge is confirmed by the inputs, otherwise "possible". Code planted by a malicious
package does something nobody has seen, so it is described as "what it can reach if it runs" and is always "possible".
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CONFIRMED, POSSIBLE = "confirmed", "possible"
JUDGEMENTS_FILE = ".aegis-ai/cve_judgments.json"      # outside .aegis/ on purpose: writing it must not trip the guard's
                                                       # protected-path check, and it never changes a verdict

# What each guard finding means for a path, the capabilities' wording and context, asset tiers and impacts: all in
# guard/rules/capabilities.json. This module only builds the graph from them.
CAPABILITIES_FILE = Path(__file__).resolve().parent / "rules" / "capabilities.json"


class CapabilitiesError(Exception):
    """capabilities.json is missing, malformed or refers to something it does not define."""


def load_capabilities(path: Path = CAPABILITIES_FILE) -> dict:
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CapabilitiesError(f"rule file missing: {path}") from None
    except ValueError as e:
        raise CapabilitiesError(f"{Path(path).name} is not valid JSON: {e}") from None
    if doc.get("schema") != 1:
        raise CapabilitiesError(f"capabilities.json: unsupported schema {doc.get('schema')!r}")
    try:
        caps, contexts = doc["capabilities"], doc["contexts"]
        for cid, c in caps.items():
            if c["context"] not in contexts:
                raise CapabilitiesError(f"capabilities.json: capability '{cid}' has unknown context '{c['context']}'")
            if c.get("confidence", "confirmed") not in ("confirmed", "possible"):
                raise CapabilitiesError(f"capabilities.json: capability '{cid}' confidence must be confirmed or possible")
            str(c["text"])
        for k, v in doc["package_capabilities"].items():
            if not set(v.get("reach", [])) <= {"process", "file_read", "file_write", "environment_read"}:
                raise CapabilitiesError(f"capabilities.json: package capability '{k}' has unknown reach {v.get('reach')}")
            str(v["text"])
        for lang, rows in (doc.get("code_patterns") or {}).items():
            for row in ([] if lang == "about" else rows):
                if row[0] not in doc["package_capabilities"]:
                    raise CapabilitiesError(f"capabilities.json: code_patterns.{lang} names unknown capability '{row[0]}'")
                re.compile(row[1])
        for kind, v in doc.get("sources", {}).items():
            if v.get("context") is not None and v["context"] not in contexts:
                raise CapabilitiesError(f"capabilities.json: source '{kind}' has unknown context '{v['context']}'")
            str(v["cut"])
        for ph, v in doc["phases"].items():
            if v["context"] not in contexts or v.get("confidence") not in ("confirmed", "possible"):
                raise CapabilitiesError(f"capabilities.json: phase '{ph}' has unknown context or confidence")
        for fid, cid in doc["findings"].items():
            if cid is not None and cid not in caps:
                raise CapabilitiesError(f"capabilities.json: finding '{fid}' refers to unknown capability '{cid}'")
        {str(k): int(v) for k, v in doc["asset_tiers"].items()}
        {str(k): str(v) for k, v in doc["impacts"].items()}
        {str(k): list(v) for k, v in doc["import_names"].items()}
    except (KeyError, TypeError, ValueError) as e:
        raise CapabilitiesError(f"capabilities.json: missing or bad value: {e}") from None
    return doc


_CAPS = load_capabilities()
SIGNAL_CAPABILITY = {k: v for k, v in _CAPS["findings"].items() if v}
CAPABILITY_TEXT = {k: v["text"] for k, v in _CAPS["capabilities"].items()}
CAPABILITY_CONTEXT = {k: v["context"] for k, v in _CAPS["capabilities"].items()}
CAPABILITY_CONFIDENCE = {k: CONFIRMED if v.get("confidence", "confirmed") == "confirmed" else POSSIBLE
                         for k, v in _CAPS["capabilities"].items()}
CONTEXTS = dict(_CAPS["contexts"])
PKG_CAPS = {k: {"text": v["text"], "reach": set(v.get("reach", [])), "channel": bool(v.get("channel"))}
            for k, v in _CAPS["package_capabilities"].items()}
PHASES = dict(_CAPS["phases"])
SOURCES = dict(_CAPS.get("sources") or {"package": {"context": None, "cut": "the path is cut at this step"}})
CAPABILITY_SNIPPET = {k for k, v in _CAPS["capabilities"].items() if v.get("show_snippet")}
CAPABILITY_REACH_NOTE = {k: v["reach_note"] for k, v in _CAPS["capabilities"].items() if v.get("reach_note")}


def source_kind(pkg: dict | None) -> str:
    """Where a record came from (capabilities.json "sources"): an agent extension (hook / MCP server / plugin), a git or
    URL install, a dependency of what the command named, or the package itself."""
    pkg = pkg or {}
    if pkg.get("bundle") in SOURCES:
        return pkg["bundle"]
    if pkg.get("direct_source"):
        return "direct"
    if pkg.get("via"):
        return "dependency"
    return "package"


def context_of(cap: str, evidence: dict, pkg: dict | None = None) -> str:
    """The context the capability's code runs in. by_location: a hook / MCP server / plugin runs in its own context
    (capabilities.json "sources"); else from the file the evidence is in (setup.py, an npm install script and the files
    it runs at install, a .pth / sitecustomize at every interpreter start, anything else when the package is used)."""
    ctx = CAPABILITY_CONTEXT[cap]
    if ctx != "by_location":
        return ctx
    own = SOURCES.get(source_kind(pkg), {}).get("context")
    if own:
        return own
    loc = str(evidence.get("location", "")).lower()
    if "setup.py" in loc or "package.json#" in loc:        # npm lifecycle scripts (sources/npm.write_lifecycle)
        return "install_exec"
    loc_file = loc.rsplit(":", 1)[0] if re.search(r":\d+$", loc) else loc
    if any(loc_file == t.lower() or loc_file.endswith("/" + t.lower()) for t in (pkg or {}).get("install_time_files") or []):
        return "install_exec"                              # a file an install script runs (`node install.js`)
    if ".pth" in loc or "sitecustomize" in loc or "usercustomize" in loc:
        return "startup_exec"
    return "import_exec"
IMPORT_NAMES = {k: list(v) for k, v in _CAPS["import_names"].items()}
ASSET_TIER = {k: int(v) for k, v in _CAPS["asset_tiers"].items()}
IMPACT = dict(_CAPS["impacts"])


def _clip(text, n: int) -> str:
    text = re.sub(r"\s+", " ", str(text)).strip()
    return text if len(text) <= n else text[:n - 1] + "…"


def _path_match(target: str, asset_path: str, profile: dict) -> bool:
    """Does a path the code names point at this asset (or a folder holding it)? ~, the home folder and ./ are normalized."""
    import os.path as _op
    home = str(Path.home())
    proj = str(profile.get("project") or "")
    def norm(x):
        x = str(x).split(" ")[0].replace("\\", "/")
        if proj and x.startswith(proj):
            x = "." + x[len(proj):]
        if x.startswith(home):
            x = "~" + x[len(home):]
        return x.rstrip("/")
    t, a = norm(target), norm(asset_path)
    if not t or not a:
        return False
    if t == a or a.startswith(t + "/"):
        return True
    t_tail, a_tail = t.lstrip("~./"), a.lstrip("~./")
    return bool(t_tail) and (a_tail == t_tail or a_tail.endswith("/" + t_tail) or _op.basename(a_tail) == t_tail and "/" in t_tail)


def import_names(package: str) -> list[str]:
    p = package.lower()
    return IMPORT_NAMES.get(p, [p.replace("-", "_").replace(".", "_")])


def _rule_matches(rule: str, path: str) -> bool:
    """Claude Code Read()/Edit() rule pattern vs a profile path (./x or ~/x); '**' and '*' as in the docs."""
    m = re.fullmatch(r"(?:Read|Edit|Write)\((.+)\)", rule.strip())
    if not m:
        return False
    pat = m.group(1).strip()
    if pat.startswith("/") and not pat.startswith("//"):
        pat = "." + pat                                   # "/x" in settings = relative to the settings file's project
    rx = re.escape(pat).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(rx, path) is not None or re.fullmatch(rx + "(/.*)?", path) is not None


# ---- inputs ------------------------------------------------------------------------------------------------------------

def load_judgements(project: Path) -> tuple[dict, list[str]]:
    """Valid CVE judgements by (package, vuln id) and the reasons any were rejected."""
    path = project / JUDGEMENTS_FILE
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        return {}, []
    except (OSError, ValueError) as e:
        return {}, [f"{JUDGEMENTS_FILE}: could not read ({type(e).__name__})"]
    out, errors = {}, []
    for i, j in enumerate(doc.get("judgements", []) if isinstance(doc, dict) else []):
        where = f"judgements[{i}]"
        if not isinstance(j, dict) or j.get("holds") not in (True, False, "unknown"):
            errors.append(f"{where}: holds must be true / false / \"unknown\"")
            continue
        bad = verify_evidence(project, j.get("evidence"))
        if bad:
            errors.append(f"{where}: " + "; ".join(bad))
            continue
        if j.get("kind") == "llm_sink":
            out[("llm_sink", str(j.get("sink", "")))] = j
        else:
            out[(str(j.get("package", "")).lower(), str(j.get("vuln", "")))] = j
    return out, errors


_ALLOWED_EVIDENCE_DIRS = (".aegis/osv/",)          # trusted text the CLI saved (OSV advisories); the rest must be project code


def verify_evidence(project: Path, evidence) -> list[str]:
    """Every quote must really be in the cited file, and the file must be trusted text: the project's own files (not its
    virtualenv / installed packages) or an OSV advisory the guard saved. Returns the problems (empty = accepted)."""
    if not isinstance(evidence, list) or not evidence:
        return ["no evidence given"]
    norm = lambda s: re.sub(r"\s+", " ", s).strip()
    bad = []
    for e in evidence:
        f, q = str((e or {}).get("file", "")), str((e or {}).get("quote", ""))
        path = (project / f).resolve()
        rel = f.replace("\\", "/").lstrip("./") if not f.startswith(".aegis") else f.replace("\\", "/")
        if project.resolve() not in path.parents or not path.is_file():
            bad.append(f"evidence file '{f}' is not in the project")
            continue
        parts = path.relative_to(project.resolve()).parts
        if any(p in (".venv", "venv", "site-packages", "node_modules") for p in parts) or \
                (parts[0].startswith(".aegis") and not any(rel.startswith(d) for d in _ALLOWED_EVIDENCE_DIRS)):
            bad.append(f"evidence file '{f}' is not trusted text (installed package or guard record)")
            continue
        raw = path.read_text(errors="replace")
        text = norm(raw) + " " + norm(_json_strings(raw) if path.suffix == ".json" else "")
        if len(norm(q)) < 4 or norm(q) not in text:
            bad.append(f"quote '{q[:40]}' is not found verbatim in '{f}'")
    return bad


def _json_strings(raw: str) -> str:
    out = []
    def walk(v):
        if isinstance(v, str): out.append(v)
        elif isinstance(v, dict): [walk(x) for x in v.values()]
        elif isinstance(v, list): [walk(x) for x in v]
    try:
        walk(json.loads(raw))
    except ValueError:
        pass
    return "\n".join(out)


# ---- graph -------------------------------------------------------------------------------------------------------------

class Graph:
    def __init__(self):
        self.nodes, self.edges = {}, []

    def node(self, nid: str, kind: str, label: str, **attrs) -> str:
        self.nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, **attrs})
        return nid

    def edge(self, src: str, dst: str, rel: str, confidence: str, evidence: str):
        if not any(e["from"] == src and e["to"] == dst and e["rel"] == rel for e in self.edges):
            self.edges.append({"from": src, "to": dst, "rel": rel, "confidence": confidence, "evidence": evidence})


def _assets(profile: dict, capability: str) -> list[dict]:
    """Assets the OS user (or, for runtime_exec, the app process) can read: readable credential files, MCP tokens written
    into config files, secrets written into the code, and - for code running inside the app - the secret-looking
    environment variables the code reads."""
    out = []
    for a in profile.get("assets", []):
        if a.get("readable_by_os_user") and not a.get("example_file"):
            out.append({"id": a["id"], "label": a["path"], "kind": a["kind"], "evidence": f"file exists and is readable ({a['path']})"})
    for m in profile.get("mcp_servers", []):
        if m.get("literal_secret_in_config"):
            src = m.get("source_file") or "MCP config"
            out.append({"id": f"asset:mcp_token:{m['name']}", "label": f"MCP '{m['name']}' token ({src})", "kind": "mcp_token",
                        "evidence": f"plaintext token in {src}"})
    code = profile.get("project_code") or {}
    for s in code.get("hardcoded_secrets", []):
        out.append({"id": f"asset:code_secret:{s['at']}", "label": f"secret in code ({s['at']})", "kind": "code_secret",
                    "evidence": f"secret-looking string at {s['at']}"})
    if capability == "runtime_exec":
        for e in code.get("env_reads", []):
            if e.get("secret_like"):
                out.append({"id": f"asset:app_env:{e['name']}", "label": f"app env var {e['name']}", "kind": "app_env_secret",
                            "evidence": f"read by the code ({', '.join(e['at'][:2])})"})
    return out


def _deny_note(profile: dict, asset_label: str) -> str | None:
    agent = next((p for p in profile.get("principals", []) if p.get("kind") == "agent"), {})
    for rule in (agent.get("permissions") or {}).get("deny", []):
        if _rule_matches(rule, asset_label.split(" ")[0]):
            return f"blocked by agent permission rule {rule}, but that rule does not apply to package code that is installed or run"
    return None


def _code_sites(package: str, code: dict) -> tuple[list[dict], list[str]]:
    """Risky calls into this package's modules, and where the package is imported (static facts from project_code)."""
    names = import_names(package)
    sites = [c for c in code.get("risky_calls", []) if any(c["call"] == n or c["call"].startswith(n + ".") for n in names)]
    imports = [at for n in names for at in (code.get("imports") or {}).get(n.split(".")[0], [])]
    return sites, imports


def build(record: dict, profile: dict, judgements: dict | None = None) -> dict:
    judgements = judgements or {}
    g = Graph()
    user = next((p for p in profile.get("principals", []) if p.get("kind") == "os_user"), {"id": "principal:os_user", "user": "?"})
    code = profile.get("project_code") or {}
    not_reachable, pending, findings_only = [], [], []
    contexts = CONTEXTS

    agent = next((p for p in profile.get("principals", []) if p.get("kind") == "agent"), None)

    def reach(src: str, capability: str, conf: str = CONFIRMED, why: str = "runs locally = user account",
              reaches=("process",), reads=(), writes=(), env_reads=(), read_conf: str = CONFIRMED):
        """src runs in this context and reaches our side. capability: the context key (one principal node per context,
        so install-time code is never shown reaching the app's environment variables); "agent": the agent itself acts
        (steered by text it read), so its own deny rules DO apply. reaches: how the code gets at things ("process" =
        anything the OS user can, "file_read" / "file_write" / "environment_read" = only through those, with the
        targets the code names). read_conf: confidence of reading an asset through a process (fallback: CONFIRMED,
        the uncertainty is on runs_as; code paths: POSSIBLE, a process may or may not read it)."""
        as_agent = capability == "agent"
        reaches = {"agent"} if as_agent else set(reaches)
        if as_agent:
            principal = g.node(agent["id"], "principal", f"agent {agent.get('name') or agent['id'].rsplit(':', 1)[-1]}",
                               note="agent permission rules apply")
        else:
            # one principal per context AND reach: a capability that only reads files must not inherit, through a shared
            # principal node, the "anything the user can" of a process capability in the same context
            narrow = "" if "process" in reaches else ":" + "+".join(sorted(reaches))
            principal = g.node(f"{user['id']}:{capability}{narrow}", "principal", f"OS user {user.get('user', '?')} ({contexts[capability]})",
                               note="only OS file permissions apply, not agent permission rules")
        assets = _assets(profile, capability)
        denied = [a["label"] for a in assets if as_agent and _deny_note(profile, a["label"])]
        if denied:                                       # the agent's own deny rules stop these
            why += f" · {len(denied)} asset(s) blocked by agent deny rules ({', '.join(denied[:2])})"
        g.edge(src, principal, "runs_as", conf, why)
        for a in assets:
            if a["label"] in denied:
                continue
            if as_agent or "process" in reaches:
                edge_conf, how = (read_conf, a["evidence"])
            elif "file_read" in reaches and any(_path_match(t, a["label"], profile) for t in reads if t):
                t = next(t for t in reads if t and _path_match(t, a["label"], profile))
                edge_conf, how = CONFIRMED, f"the code reads this file directly ({t})"
            elif "file_read" in reaches and any(t is None for t in reads):
                edge_conf, how = POSSIBLE, "the files the code reads are not known in advance → anything readable"
            else:
                continue
            note = None if as_agent else _deny_note(profile, a["label"])
            aid = g.node(a["id"], "asset", a["label"], asset_kind=a["kind"], tier=ASSET_TIER.get(a["kind"], 3))
            g.edge(principal, aid, "can_read", edge_conf, how + (f" · {note}" if note else ""))
            if a["kind"] in IMPACT:
                g.edge(aid, g.node(f"impact:{IMPACT[a['kind']]}", "impact", IMPACT[a["kind"]]), "enables", POSSIBLE,
                       "what the credential grants")
        for o in profile.get("capabilities", []) or []:          # our side: agent, MCP, project code, push, agent config
            via = reaches & set(o.get("reached_by", []))
            if not via:
                continue
            edge_conf, how = (read_conf if ("process" in via or "agent" in via) else POSSIBLE), "reachable (" + ", ".join(sorted(via)) + ")"
            if "file_write" in via and any(t and any(_path_match(t, x, profile) for x in o.get("paths", []) or [o.get("path", "")]) for t in writes):
                edge_conf, how = CONFIRMED, "the code writes this config or code file directly"
            if "environment_read" in via and set(t for t in env_reads if t) & set(o.get("env_names", [])):
                edge_conf, how = CONFIRMED, "the code reads this server's token env var directly"
            oid = g.node(o["id"], "ours", o["label"], tier=o.get("tier", 2))
            g.edge(principal, oid, "can_use", edge_conf, how)
            g.edge(oid, g.node(f"impact:{o['gives']}", "impact", o["gives"]), "enables", POSSIBLE, "what our capability grants")

    def code_paths(name: str, pid: str, items: list[dict], src_kind: str = "package") -> bool:
        """Paths from what the package's code does (package_caps.py): one capability node per (execution phase, kind),
        each reaching only what that kind reaches - a read of ~/.ssh/id_rsa is its own, confirmed edge, not folded into
        "runs a process, so anything". A network connection reaches nothing by itself: it is a node in the graph and a
        note on the phase's other capabilities (what they read can be sent out)."""
        made = False
        by_phase: dict[str, list] = {}
        for c in items:
            if c.get("kind") in PKG_CAPS and c.get("when") in PHASES:
                by_phase.setdefault(c["when"], []).append(c)
        own = SOURCES.get(src_kind, {}).get("context")              # a hook / MCP server / plugin runs in its own context
        for phase in sorted(by_phase, key=lambda x: list(PHASES).index(x)):
            its = by_phase[phase]
            run_ctx = own or PHASES[phase]["context"]
            when = CONTEXTS[own] if own else PHASES[phase]["text"]
            conf = CONFIRMED if PHASES[phase]["confidence"] == "confirmed" else POSSIBLE
            channel = [c.get("target") or "address decided at runtime" for c in its if PKG_CAPS[c["kind"]].get("channel")]
            for kind in dict.fromkeys(c["kind"] for c in its):
                ks = [c for c in its if c["kind"] == kind]
                tg = list(dict.fromkeys(_clip(c["target"], 30) for c in ks if c.get("target")))
                label = f"{when}: {PKG_CAPS[kind]['text']}" + (f" ({', '.join(tg[:2])}{' and more' if len(tg) > 2 else ''})" if tg else "")
                cid = g.node(f"cap:{name}:code:{phase}:{kind}", "capability", label, source=src_kind, capability=kind)
                g.edge(pid, cid, "can_do", CONFIRMED, "static code analysis " + ", ".join(c["at"] for c in ks[:3]))
                reaches = PKG_CAPS[kind]["reach"]
                if not reaches:
                    continue                             # a network connection / env write: no asset through it alone
                why = f"{when}, runs with OS user permissions" if conf == CONFIRMED else "runs only when that function is called (no caller found)"
                if channel:
                    why += f" · has an outbound connection, so what it reads can be sent out ({_clip(channel[0], 50)})"
                reach(cid, run_ctx, conf, why, reaches=reaches,
                      reads=[c.get("target") for c in ks if c["kind"] == "file_read"],
                      writes=[c.get("target") for c in ks if c["kind"] in ("file_write", "file_delete")],
                      env_reads=[c.get("target") for c in ks if c["kind"] == "environment_read"], read_conf=POSSIBLE)
                made = True
        return made

    for pkg in record.get("packages", []):
        if pkg.get("verdict") not in ("BLOCK", "NEEDS_HUMAN_REVIEW"):
            continue
        name, ver = str(pkg.get("package", "?")), str(pkg.get("version", ""))
        reasons = list(dict.fromkeys(str(e.get("label") or e.get("rule")) for e in pkg.get("evidence", [])
                                     if e.get("rule") not in ("score",)))
        pid = g.node(f"pkg:{name}@{ver}", "package", f"{name} {ver}".strip(), verdict=pkg.get("verdict"), reasons=reasons[:4])
        items = (pkg.get("capabilities") or {}).get("items") or []
        n_before = sum(1 for e in g.edges if e["rel"] in ("can_read", "can_use"))
        used = code_paths(name, pid, items, source_kind(pkg)) if items else False
        if used and sum(1 for e in g.edges if e["rel"] in ("can_read", "can_use")) == n_before:
            what = ", ".join(dict.fromkeys(f"{PKG_CAPS[c['kind']]['text']} ({_clip(c['target'], 30)})" for c in items
                                           if c.get("target") and c.get("kind") in PKG_CAPS))[:120]
            findings_only.append({"package": f"{name} {ver}", "verdict": pkg.get("verdict"),
                                  "why": f"what the code does ({what or 'target unknown'}) reaches no asset or capability in this environment"})
        by_cap: dict[tuple, list] = {}             # fallback: what the verdict reasons suggest, when the code was not seen
        for e in pkg.get("evidence", []):
            cap = SIGNAL_CAPABILITY.get(e.get("rule"))
            if e.get("rule") == "install_hook" and e.get("note"):
                cap = None                              # an install hook with no dangerous call at install time
            if cap and (not used or CAPABILITY_CONTEXT[cap] == "agent"):   # text aimed at the agent is not code
                by_cap.setdefault((cap, context_of(cap, e, pkg)), []).append(e)
        used = used or bool(by_cap)
        for (cap, capability), evs in by_cap.items():
            def shown(e):
                snip = f": {_clip(e.get('snippet', ''), 50)}" if cap in CAPABILITY_SNIPPET and e.get("snippet") else ""
                return f"{e.get('label', e.get('rule'))} ({e.get('location', '')}{snip})"
            label = " + ".join(shown(e) for e in evs[:3])
            suffix = "" if CAPABILITY_CONTEXT[cap] != "by_location" else f":{capability}"
            fid = g.node(f"finding:{name}:{cap}{suffix}", "finding", label)
            g.edge(pid, fid, "has_finding", CONFIRMED, "guard decision record " + ", ".join(str(e.get("location", "")) for e in evs[:3]))
            cid = g.node(f"cap:{name}:{cap}{suffix}", "capability", CAPABILITY_TEXT[cap], source=source_kind(pkg))
            g.edge(fid, cid, "gives", CAPABILITY_CONFIDENCE[cap], "verdict reason → fallback capability table (code not seen)")
            if capability == "agent" and agent is None:
                findings_only.append({"package": f"{name} {ver}", "verdict": pkg.get("verdict"),
                                      "why": "no agent information (Profile), so the agent-hijack path cannot be linked"})
                continue
            reach(cid, capability, POSSIBLE, CAPABILITY_REACH_NOTE.get(cap, "runs as the user account, but what the code does is unknown → anything reachable")
                  if capability != "agent" else "if the agent reads the package's files, it may follow instructions in them")
        adv = pkg.get("advice") or {}
        for grp in adv.get("vuln_groups", []) or []:
            vid = (grp.get("ids") or ["?"])[0]
            cve = next((i for i in grp.get("ids", []) if str(i).startswith("CVE-")), vid)
            used = True
            fid = g.node(f"finding:{name}:{vid}", "finding", f"{cve} ({grp.get('severity') or '?'})", vuln_ids=grp.get("ids"),
                         cvss=grp.get("cvss"), cwe=grp.get("cwe"))
            g.edge(pid, fid, "has_vuln", CONFIRMED, "OSV advisory")
            sites, imports = _code_sites(name, code)
            j = next((judgements[k] for k in ((name.lower(), i) for i in grp.get("ids", [])) if k in judgements), None)
            if j is not None and j.get("holds") is False:
                not_reachable.append({"package": f"{name} {ver}", "vuln": cve, "why": j.get("condition_not_met") or j.get("reason", ""),
                                      "by": "AI judgement (evidence verified)", "evidence": j.get("evidence")})
                continue
            if not imports and not sites:
                not_reachable.append({"package": f"{name} {ver}", "vuln": cve, "by": "rule",
                                      "why": "the code under development does not import this package directly (use by other packages internally is not checked)"})
                continue
            cid = g.node(f"cap:{name}:runtime:{vid}", "capability", CAPABILITY_TEXT["runtime_exec"])
            holds = j is not None and j.get("holds") is True
            g.edge(fid, cid, "gives", CONFIRMED if holds else POSSIBLE,
                   ("AI judgement (evidence verified): attack condition from the advisory " + str(j.get("condition", ""))[:80]) if holds
                   else f"CVSS {grp.get('cvss') or '?'} / {grp.get('cwe') or '?'} (whether the condition holds is not checked)")
            if j is not None and j.get("holds") is True:
                site = (j.get("site") or (sites[0]["at"] if sites else imports[0]))
                sid = g.node(f"code:{site}", "code", f"{site} {j.get('call', '')}".strip())
                g.edge(cid, sid, "reached_at", CONFIRMED, "AI judgement (evidence verified): " + str(j.get("condition", ""))[:120])
                reach_from = sid
            else:
                site = sites[0]["at"] if sites else imports[0]
                label = f"{site} {sites[0]['call']}" if sites else f"{site} import"
                sid = g.node(f"code:{site}", "code", label)
                why = "judgement pending: needs an AI judgement on whether the attack condition holds in this code" if j is None else "AI judgement: unknown"
                g.edge(cid, sid, "reached_at", POSSIBLE, why)
                if j is None:
                    pending.append({"package": name, "version": ver, "vuln_ids": grp.get("ids"), "cve": cve,
                                    "sites": [{"call": s["call"], "at": s["at"], "loader": s.get("loader"), "symbol": s.get("symbol")} for s in sites],
                                    "imports": imports[:5]})
                reach_from = sid
            reach(reach_from, "runtime_exec")
        if not used:
            labels = sorted({str(e.get("label") or e.get("rule")) for e in pkg.get("evidence", []) if e.get("rule") != "score"})
            findings_only.append({"package": f"{name} {ver}", "verdict": pkg.get("verdict"),
                                  "why": (f"the evidence ({', '.join(labels[:4])}) does not say what runs, so it is not linked into a path" if labels
                                          else "no evidence to link into a path")})
    # Model output reaching a code/command sink in the project's own code. The entry is the model's
    # reply, which an attacker can steer with prompt injection (a web page, a file, a message the agent reads).
    for c in code.get("llm_sink_candidates", []) or []:
        j = judgements.get(("llm_sink", c["sink"]))
        label = f"LLM reply → {c['sink_call']} ({c['sink']})"
        if j is not None and j.get("holds") is False:
            not_reachable.append({"package": label, "vuln": "prompt injection", "by": "AI judgement (evidence verified)",
                                  "why": j.get("condition_not_met") or j.get("reason", ""), "evidence": j.get("evidence")})
            continue
        holds = j is not None and j.get("holds") is True
        eid = g.node(f"entry:llm:{c['llm_call']}", "package", f"LLM reply ({c['llm_call']}, {c['sdk']})", verdict="AGENT_CODE")
        fid = g.node(f"finding:llm:{c['llm_call']}", "finding", "reply manipulated by prompt injection")
        g.edge(eid, fid, "can_be", CONFIRMED if holds else POSSIBLE,
               "if outside text reaches the model input, an attacker can choose the reply" + ("" if holds else " (judgement pending)"))
        sid = g.node(f"code:{c['sink']}", "code", f"{c['sink']} {c['sink_call']}")
        g.edge(fid, sid, "reaches", CONFIRMED if holds else POSSIBLE,
               ("AI judgement (evidence verified): " + str(j.get("condition", ""))[:120]) if holds
               else f"model call and dangerous function in the same function ({c['symbol'] or 'module'}) (static candidate)")
        cid = g.node(f"cap:llm:{c['sink']}", "capability", CAPABILITY_TEXT["runtime_exec"])
        g.edge(sid, cid, "gives", CONFIRMED, f"{c['sink_call']} runs the text it gets as code or a command")
        reach(cid, "runtime_exec")
        if j is None:
            pending.append({"type": "llm_sink", "llm_call": c["llm_call"], "sdk": c["sdk"], "sink": c["sink"],
                            "sink_call": c["sink_call"], "symbol": c["symbol"]})
    paths = _enumerate(g)
    return {"schema": "aegis-attack-paths/0.1", "nodes": list(g.nodes.values()), "edges": g.edges, "paths": paths,
            "bottlenecks": _bottlenecks(g, paths), "not_reachable": not_reachable, "pending_judgements": pending,
            "findings_without_path": findings_only}


def _enumerate(g: Graph) -> list[dict]:
    out_edges = {}
    for e in g.edges:
        out_edges.setdefault(e["from"], []).append(e)
    paths = []

    def walk(nid, trail, seen):
        node = g.nodes[nid]
        nxt = [e for e in out_edges.get(nid, []) if e["to"] not in seen]
        if node["kind"] in ("asset", "ours"):
            paths.append(trail)
            return                                   # impacts are shown on the asset, not as separate paths
        for e in nxt:
            walk(e["to"], trail + [e], seen | {e["to"]})

    for nid, n in g.nodes.items():
        if n["kind"] == "package":
            walk(nid, [], {nid})
    result = []
    for trail in paths:
        conf = CONFIRMED if all(e["confidence"] == CONFIRMED for e in trail) else POSSIBLE
        asset = g.nodes[trail[-1]["to"]]
        impact = [g.nodes[e["to"]]["label"] for e in g.edges if e["from"] == asset["id"] and e["rel"] == "enables"]
        pkg = g.nodes[trail[0]["from"]]
        result.append({"package": pkg["label"], "verdict": pkg.get("verdict"), "asset": asset["label"], "asset_tier": asset.get("tier", 3),
                       "target_kind": asset["kind"],
                       "impact": impact, "confidence": conf, "steps": [trail[0]["from"]] + [e["to"] for e in trail],
                       "edges": trail})
    result.sort(key=lambda p: (p["asset_tier"], p["confidence"] != CONFIRMED, p["verdict"] != "BLOCK", p["package"], p["asset"]))
    return result


def _bottlenecks(g: Graph, paths: list[dict]) -> list[dict]:
    if not paths:
        return []
    count, first = {}, {}
    for p in paths:
        keys = {}
        for nid in p["steps"][1:-1]:                     # path order, not set order: ties stay in the same order every run
            if g.nodes[nid]["kind"] in ("capability", "principal", "code"):
                keys.setdefault((g.nodes[nid]["kind"], g.nodes[nid]["label"]), nid)   # same step shown once (by its label)
        for key, nid in keys.items():
            first.setdefault(key, nid)
            count[first[key]] = count.get(first[key], 0) + 1
    advice = {"principal": "keeping credential files away from the dev account (separate user, secret manager) cuts the paths after this step",
              "code": "switching this call to a safe form (e.g. yaml.safe_load) cuts the path at this step"}
    agent_fix = "adding these credential files to the agent's deny rules (e.g. Read(~/.ssh/**)) cuts the paths after this step"

    def fix(n):
        node = g.nodes[n]
        if node["kind"] == "principal" and node.get("note") == "agent permission rules apply":
            return agent_fix
        if node["kind"] == "capability":                  # how to cut it depends on where it came from
            return (SOURCES.get(node.get("source") or "package") or SOURCES["package"])["cut"]
        return advice[node["kind"]]
    top = sorted(count.items(), key=lambda kv: -kv[1])[:3]
    return [{"node": g.nodes[n]["label"], "kind": g.nodes[n]["kind"], "paths": c, "of": len(paths), "fix": fix(n)}
            for n, c in top if c > 1]


# ---- text --------------------------------------------------------------------------------------------------------------

def report_text(result: dict, max_paths: int = 12) -> str:
    paths = result["paths"]
    labels = {n["id"]: n["label"] for n in result["nodes"]}
    lines = []
    conf = sum(p["confidence"] == CONFIRMED for p in paths)
    assets = sorted({p["asset"] for p in paths})
    lines.append(f"[AegisPilot attack path] {len(paths)} path(s) (confirmed {conf}, possible {len(paths) - conf}) · {len(assets)} asset(s) reached")
    groups: dict = {}                        # paths that differ only in the asset are shown on one line
    for p in paths:
        groups.setdefault((tuple(p["steps"][:-1]), p["confidence"]), []).append(p)
    for i, ((prefix, conf_), grp) in enumerate(list(groups.items())[:max_paths], 1):
        chain = " → ".join(labels[s] for s in prefix)
        if len(grp) == 1:
            target = grp[0]["asset"]
        else:
            shown = [g["asset"] for g in grp[:4]]
            target = f"{len(grp)} assets: {'; '.join(shown)}" + (f" and {len(grp) - 4} more" if len(grp) > 4 else "")
        impacts = list(dict.fromkeys(x for g in grp for x in g["impact"]))
        imp = f"  ⇒ {'; '.join(impacts)}" if impacts else ""
        lines.append(f"{i:>2}. [{conf_}] {chain} → {target}{imp}")
        notes = list(dict.fromkeys(e["evidence"].split(" · ", 1)[1] for g in grp for e in g["edges"] if " · " in e["evidence"]))
        if notes:
            lines.append(f"    note: {notes[0]}")
    if len(groups) > max_paths:
        lines.append(f"    … {len(groups) - max_paths} more line(s) (--json for all)")
    for b in result["bottlenecks"]:
        lines.append(f"choke point: {b['node']} (paths {b['paths']}/{b['of']}): {b['fix']}")
    for n in result["not_reachable"]:
        lines.append(f"not a path: {n['package']} {n['vuln']}: {n['why']} [{n['by']}]")
    for f in result["findings_without_path"]:
        lines.append(f"no path: {f['package']} ({f['verdict']}): {f['why']}")
    if result["pending_judgements"]:
        lines.append(f"{len(result['pending_judgements'])} judgement(s) pending: whether a vulnerability condition or LLM reply flow holds "
                     "in the code; get a judgement with `guard_cli.py paths --judge` to turn these into confirmed / not a path")
    for e in result.get("judgement_errors", []):
        lines.append(f"judgement rejected: {e}")
    if not paths and not result["not_reachable"] and not result["findings_without_path"]:
        lines.append("no reviewed or blocked packages, so there are no paths")
    lines.append("* Paths are an explanation only. They do not change the allow / block verdict.")
    return "\n".join(lines)


# ---- AI judgement request ----------------------------------------------------------------------------------------------

def save_osv(project: Path, vuln_ids: list[str], fetch=None) -> dict:
    """Fetch the OSV advisories (trusted text) into .aegis/osv/ so the judgement can quote them. {id: relative path}."""
    import urllib.request
    fetch = fetch or (lambda vid: urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=15).read())
    out = {}
    d = project / ".aegis" / "osv"
    for vid in vuln_ids:
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,80}", vid or ""):
            continue
        p = d / f"{vid}.json"
        try:
            if not p.is_file():
                raw = fetch(vid)
                doc = json.loads(raw)
                import safe_write
                safe_write.write_text(project / ".aegis", f"osv/{vid}.json", json.dumps({"id": doc.get("id"), "summary": doc.get("summary"), "details": doc.get("details"),
                                         "affected_ranges": [r for a in doc.get("affected", []) for r in a.get("ranges", [])][:5]},
                                        ensure_ascii=False, indent=1))
            out[vid] = str(p.relative_to(project))
        except Exception:
            continue
    return out


def cve_judgement_request(project: Path, pending: list[dict], osv_files: dict) -> str:
    """The card the user's agent gets. Built only from trusted inputs: OSV text (saved file), the user's code locations,
    fixed values from the guard record. No package code or description is included."""
    items, llm_items = [], []
    for p in pending:
        if p.get("type") == "llm_sink":
            llm_items.append(f"- model call {p['llm_call']} ({p['sdk']}) → {p['sink_call']} ({p['sink']}) in the same function {p['symbol'] or '(module)'}")
            continue
        files = [osv_files[i] for i in p["vuln_ids"] if i in osv_files]
        sites = "; ".join(f"{s['at']} {s['call']}" + (f"(Loader={s['loader']})" if s.get("loader") else "") for s in p["sites"]) or "none"
        items.append(f"- package={p['package']} version={p['version']} vuln={p['vuln_ids'][0]} ({p['cve']})\n"
                     f"  advisory text: {', '.join(files) or 'could not save (check internet access)'}\n"
                     f"  where the code uses this package: dangerous calls {sites} / import {', '.join(p['imports']) or 'none'}")
    llm_part = "" if not llm_items else f"""
[LLM reply → dangerous function] {len(llm_items)} item(s): decide whether the model's reply (an attacker can choose its content through prompt injection) reaches that function without validation.
{chr(10).join(llm_items)}
- reaches it (the reply text, as is or only reformatted, becomes an argument of that function): holds=true
- does not reach it (only other values go in, allowlist check, fixed command, etc.): holds=false, one sentence in condition_not_met
- cannot tell: holds="unknown"
- For these items, quote only this project's code files as evidence. Format: {{"kind": "llm_sink", "sink": "<file:line>", "llm_call": "<file:line>", "holds": ..., "condition": "...", "condition_not_met": "...", "evidence": [...]}}
"""
    if not items:
        return f"""[AegisPilot attack path] Please judge {len(llm_items)} candidate(s) in this project's code where a model reply flows into a dangerous function.
Read: only this project's code (not virtualenvs or installed package folders).{llm_part}
Write the file {JUDGEMENTS_FILE} with the Write tool: {{"judgements": [ ... ]}}. A judgement is rejected if a quote is not in its file.
Then run `python3 {Path(__file__).resolve().parent / 'guard_cli.py'} paths --project {project}` and show the result to the user."""
    return f"""[AegisPilot attack path] Please judge whether the following vulnerabilities ({len(items)}) actually hold in this project's code.
Read: the advisory files below and this project's code (not virtualenvs or installed package folders). Do not read the package's own code or description.
{chr(10).join(items)}
Task: for each vulnerability, find the attack condition in the advisory (which function must get which input), then decide whether that condition holds in this project's code.
- holds: holds=true, and the code location where the attack input comes in as site (file:line)
- does not hold: holds=false, and one sentence in condition_not_met saying why
- cannot tell from the code alone: holds="unknown"
- In evidence, quote strings verbatim from the advisory file and the code files (paths relative to the project). A judgement is rejected if a quote is not in its file.
Write the file {JUDGEMENTS_FILE} with the Write tool. Format:
{{"judgements": [{{"package": "<package>", "vuln": "<vuln id>", "condition": "<attack condition from the advisory, one sentence>", "holds": true|false|"unknown",
  "site": "<file:line>", "call": "<call>", "condition_not_met": "<why it does not hold>",
  "evidence": [{{"file": "<path relative to the project>", "quote": "<exact string from that file>"}}]}}]}}{llm_part}
Then run `python3 {Path(__file__).resolve().parent / 'guard_cli.py'} paths --project {project}` and show the result to the user."""


def run(project_dir, profile: dict | None = None, record: dict | None = None, decision_id: str | None = None) -> dict:
    """Paths for one guard decision (decision_id, e.g. D7f3a) or the latest one."""
    project = Path(project_dir).resolve()
    if record is None:
        from review_report import load_review
        record = load_review(project, decision_id) or {"packages": []}
    if profile is None:
        from env_profile import collect
        profile = collect(project)
    judgements, errors = load_judgements(project)
    result = build(record, profile, judgements)
    result["judgement_errors"] = errors
    result["record_command"] = record.get("command")
    result["decision_id"] = record.get("decision_id")
    return result
