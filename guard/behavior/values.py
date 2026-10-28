"""Shared value model of the behavior analysis (guard/behavior): what an expression is worth without running it.

A value is either known (`c`, a str / bytes / int / float / bool / None / list / tuple / dict of known values), a reference
to something callable or importable (`ref`, a dotted name such as "subprocess.run"), or unknown. Every value carries
taint `tags` - where its data came from:
  NET      fetched from the network          SECRET   credential file, browser/wallet store, whole environment
  SECRET_ENV  one secret-looking env var     SYSINFO  user name, host name, working directory, OS details
  DECODED  produced by a decoder (base64, zlib, hex, char codes...)     LOCAL  read from a file of the package itself
The classifiers here look at RESOLVED values (a path, a host, a command), never at source text.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

NET, SECRET, SECRET_ENV, SYSINFO, DECODED, LOCAL = "NET", "SECRET", "SECRET_ENV", "SYSINFO", "DECODED", "LOCAL"
NOVAL = object()
POLICY_PATH = Path(__file__).resolve().parents[1] / "rules" / "behavior.json"


class Val:
    __slots__ = ("c", "tags", "ref", "meta")

    def __init__(self, c=NOVAL, tags=frozenset(), ref=None, meta=None):
        self.c, self.tags, self.ref, self.meta = c, frozenset(tags), ref, meta

    @property
    def known(self) -> bool:
        return self.c is not NOVAL

    def s(self):
        """The known text (str, or bytes decoded leniently), else None."""
        if isinstance(self.c, str):
            return self.c
        if isinstance(self.c, (bytes, bytearray)):
            return bytes(self.c).decode("utf-8", "replace")
        return None

    def __repr__(self):
        return f"Val({'?' if self.c is NOVAL else repr(self.c)[:40]}, {sorted(self.tags)}, ref={self.ref})"


UNKNOWN = Val()


def K(c, tags=frozenset()) -> Val:
    return Val(c, tags)


def U(*vals_or_tags) -> Val:
    """Unknown value carrying the union of the given tags / the tags of the given values."""
    tags = set()
    for v in vals_or_tags:
        if isinstance(v, Val):
            tags |= v.tags
        elif isinstance(v, (set, frozenset, list, tuple)):
            tags |= set(v)
        elif isinstance(v, str):
            tags.add(v)
    return Val(NOVAL, tags)


def tags_of(*vals) -> frozenset:
    out = set()
    for v in vals:
        if isinstance(v, Val):
            out |= v.tags
            if isinstance(v.c, (list, tuple)):
                for x in v.c:
                    if isinstance(x, Val):
                        out |= x.tags
    return frozenset(out)


class Policy:
    def __init__(self, path: Path = POLICY_PATH, doc: dict | None = None):
        if doc is None:
            doc = json.loads(path.read_text(encoding="utf-8"))
        self.doc = doc
        self.findings = doc["findings"]
        self.auto = set(doc["phases"]["auto"])
        v = doc["values"]
        self.credential = [re.compile(p, re.I) for p in v["credential_path"]]
        self.autostart = [re.compile(p, re.I) for p in v["autostart_path"]]
        self.secret_env = re.compile(v["secret_env"], re.I)
        self.collector = re.compile(v["collector_host"], re.I)
        self.messenger = re.compile(v["messenger_url"], re.I)
        self.build = set(v["build_commands"])
        self.interpreters = set(v["interpreters"])
        self.limits = doc["limits"]

    def action(self, finding: str, phase: str) -> str | None:
        f = self.findings[finding]
        if f.get("phases") and phase not in f["phases"]:
            return None
        return f["auto"] if phase in self.auto else f["call"]


_POLICY = None


def policy() -> Policy:
    """The policy of the rules in use: rules/behavior.json with the rule modules on top (rule_engine.current)."""
    global _POLICY
    if _POLICY is None:
        try:
            import rule_engine
            doc = rule_engine.current().raw.get("behavior")
        except ImportError:                              # used on its own, outside the guard folder
            doc = None
        _POLICY = Policy(doc=doc) if doc is not None else Policy()
    return _POLICY


def norm_path(p: str) -> str:
    p = p.replace("\\", "/").strip().strip("'\"")
    p = re.sub(r"%(userprofile|homepath|home)%|\$home|\$env:userprofile|\$\{?home\}?|^~", "~", p, flags=re.I)
    p = re.sub(r"%appdata%|\$env:appdata", "~/appdata/roaming", p, flags=re.I)
    p = re.sub(r"%localappdata%|\$env:localappdata", "~/appdata/local", p, flags=re.I)
    return re.sub(r"/+", "/", p).lower()


def path_class(p) -> str | None:
    """'credential' | 'autostart' | 'local' (relative, inside the package) | None (somewhere else)."""
    if not isinstance(p, str) or not p:
        return None
    n = norm_path(p)
    pol = policy()
    if any(r.search(n) for r in pol.credential):
        return "credential"
    if any(r.search(n) for r in pol.autostart):
        return "autostart"
    if not n.startswith(("/", "~")) and not re.match(r"^[a-z]:/", n) and "appdata" not in n and ".." not in n.split("/")[:1]:
        return "local"
    return None


def host_of(url: str) -> str:
    u = url.strip()
    if "://" not in u:
        u = "//" + u
    try:
        return (urlsplit(u).hostname or "").lower()
    except ValueError:
        return ""


def endpoint_class(target) -> str | None:
    """'messenger' (bot API / webhook), 'collector' (OAST / request bin / tunnel / IP lookup), 'raw_ip' or None."""
    if not isinstance(target, str) or not target:
        return None
    pol = policy()
    if pol.messenger.search(target):
        return "messenger"
    host = host_of(target)
    if host and pol.collector.search(host):
        return "collector"
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if not ip.is_loopback and not ip.is_unspecified and not ip.is_link_local:   # 169.254.169.254: cloud metadata
            return "raw_ip"
    except ValueError:
        pass
    return None


def is_secret_env(name) -> bool:
    return isinstance(name, str) and bool(policy().secret_env.search(name))
