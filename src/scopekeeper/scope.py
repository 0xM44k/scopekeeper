"""Scope file loading and target matching. No DNS lookups are ever made."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
NOT_TLD_EXT = {"txt", "xml", "json", "log", "out", "html", "htm", "csv", "pdf", "conf", "cfg", "yml", "yaml",
               "lst", "list", "gnmap", "nmap", "pcap", "bak", "gz", "tar", "png", "jpg", "jpeg", "db", "sql", "tmp"}


class ScopeError(Exception):
    pass


def parse_time(s, label):
    if not isinstance(s, str):
        raise ScopeError(f"{label}: expected an ISO 8601 string with a timezone, e.g. 2026-11-01T09:00:00Z")
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as e:
        raise ScopeError(f"{label}: {s!r} is not ISO 8601") from e
    if dt.tzinfo is None:
        raise ScopeError(f"{label}: {s!r} has no timezone; add Z or an offset")
    return dt.astimezone(timezone.utc)


def _list(d, key, label):
    v = d.get(key, [])
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ScopeError(f"{label}.{key}: expected a list of strings")
    return v


def load_scope(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            raw = fh.read()
        data = json.loads(raw)
    except OSError as e:
        raise ScopeError(f"{path}: {e.strerror}") from e
    except json.JSONDecodeError as e:
        raise ScopeError(f"{path}: not valid JSON ({e.msg} at line {e.lineno})") from e
    if not isinstance(data, dict):
        raise ScopeError(f"{path}: expected a JSON object")
    for k in ("engagement", "authorized_by", "window", "in_scope"):
        if k not in data:
            raise ScopeError(f"{path}: missing required field {k!r}")
    win = data["window"]
    if not isinstance(win, dict):
        raise ScopeError("window: expected {\"start\": ..., \"end\": ...}")
    start, end = parse_time(win.get("start"), "window.start"), parse_time(win.get("end"), "window.end")
    if end <= start:
        raise ScopeError("window.end must be after window.start")
    scope = {"engagement": str(data["engagement"]), "authorized_by": str(data["authorized_by"]),
             "start": start, "end": end}
    for side in ("in_scope", "out_of_scope"):
        block = data.get(side, {})
        if not isinstance(block, dict):
            raise ScopeError(f"{side}: expected an object")
        domains = [d.lower().rstrip(".") for d in _list(block, "domains", side)]
        nets = []
        for c in _list(block, "cidrs", side) + _list(block, "ips", side):
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError as e:
                raise ScopeError(f"{side}: {c!r} is not an IP or CIDR") from e
        for d in domains:
            bare = d[2:] if d.startswith("*.") else d
            if not HOST_RE.match(bare):
                raise ScopeError(f"{side}.domains: {d!r} is not a valid domain or *.domain")
        scope[side] = {"domains": domains, "nets": nets}
    if not (scope["in_scope"]["domains"] or scope["in_scope"]["nets"]):
        raise ScopeError("in_scope is empty: list at least one domain, CIDR or IP")
    scope["raw_sha256"] = __import__("hashlib").sha256(raw.encode("utf-8")).hexdigest()
    return scope


def normalise_target(t):
    """Return ('ip', ip_address) | ('net', network) | ('host', name) or raise ValueError."""
    t = t.strip()
    if "://" in t:
        host = urlparse(t).hostname
        if not host:
            raise ValueError("URL has no host")
        t = host
    if t.startswith("[") and "]" in t:
        t = t[1:t.index("]")]
    try:
        return "ip", ipaddress.ip_address(t)
    except ValueError:
        pass
    try:
        return "net", ipaddress.ip_network(t, strict=False)
    except ValueError:
        pass
    if t.count(":") == 1:                       # host:port
        t = t.split(":")[0]
    t = t.lower().rstrip(".")
    try:
        return "ip", ipaddress.ip_address(t)
    except ValueError:
        pass
    if HOST_RE.match(t):
        return "host", t
    raise ValueError(f"{t!r} is not an IP, CIDR, hostname or URL")


def _domain_match(host, entries):
    for e in entries:
        if e.startswith("*."):
            if host.endswith(e[1:]) and host != e[2:]:
                return e
        elif host == e:
            return e
    return None


def _net_match(kind, val, nets):
    for n in nets:
        if kind == "ip" and val.version == n.version and val in n:
            return str(n)
        if kind == "net" and val.version == n.version and val.subnet_of(n):
            return str(n)
    return None


def check_target(scope, target, now):
    """Verdict for one target: {"target","verdict": "in"|"out","reason"}. Fails closed."""
    if now < scope["start"] or now > scope["end"]:
        return {"target": target, "verdict": "out", "reason": f"outside the authorised window ({scope['start'].isoformat()} to {scope['end'].isoformat()})"}
    try:
        kind, val = normalise_target(target)
    except ValueError as e:
        return {"target": target, "verdict": "out", "reason": f"cannot classify target: {e}"}
    for side, verdict in (("out_of_scope", "out"), ("in_scope", "in")):
        s = scope[side]
        hit = _domain_match(val, s["domains"]) if kind == "host" else _net_match(kind, val, s["nets"])
        if hit:
            why = f"matches {'excluded' if side == 'out_of_scope' else 'in-scope'} entry {hit}"
            return {"target": target, "verdict": verdict, "reason": why}
    note = " Hostnames are not resolved; list the IP or CIDR if the host's address is what you are authorised to test." if kind == "host" else ""
    return {"target": target, "verdict": "out", "reason": "not listed in scope." + note}
