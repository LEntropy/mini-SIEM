"""
Log source parsers. Each returns a list of normalized core.Event objects so
downstream detection/correlation can treat every source uniformly.

Supported sources:
  - apache access log (Combined Log Format)
  - apache error log (PHP errors)
  - auth log (sshd failed/accepted password)
  - NAC event log  (JSON lines emitted by the NAC project)
  - PMS event log  (JSON lines emitted by the PMS project)
  - LureTrace export (JSON lines of decoy activity from the LureTrace sensor)

The NAC/PMS formats are JSON-lines so any producer can emit them; see
samples/ and docs/TEST_GUIDE.md for the expected fields.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import List, Iterable

from core import Event

# ---- Apache Combined Log Format ----
_ACCESS = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
# Apache error log with a PHP message
_ERROR = re.compile(r'\[(?P<ts>[^\]]+)\].*?(?:\[client (?P<ip>[\d.]+)[^\]]*\])?\s*(?P<msg>PHP .+)$')
# sshd auth lines
_AUTH = re.compile(
    r'(?P<ts>\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<result>Failed password|Accepted password) for (?:invalid user )?(?P<user>\S+)'
    r'\s+from\s+(?P<ip>[\d.]+)'
)


def parse_apache_access(text: str, host: str = "") -> List[Event]:
    out = []
    for line in text.splitlines():
        m = _ACCESS.match(line)
        if not m:
            continue
        req = m.group("req")
        parts = req.split()
        method = parts[0] if parts else ""
        target = parts[1] if len(parts) > 1 else ""
        out.append(Event(
            source="apache", kind="request", ts=m.group("ts"), ip=m.group("ip"),
            host=host, status=int(m.group("status")), path=target,
            ua=(m.group("ua") or ""), data={"method": method}, raw=line))
    return out


def parse_apache_error(text: str, host: str = "") -> List[Event]:
    out = []
    for line in text.splitlines():
        m = _ERROR.search(line)
        if not m:
            continue
        out.append(Event(
            source="apache", kind="php_error", ts=m.group("ts") or "",
            ip=(m.group("ip") or ""), host=host,
            data={"message": m.group("msg")}, raw=line))
    return out


def parse_auth(text: str) -> List[Event]:
    out = []
    for line in text.splitlines():
        m = _AUTH.search(line)
        if not m:
            continue
        failed = m.group("result").startswith("Failed")
        out.append(Event(
            source="auth", kind="auth_fail" if failed else "auth_ok",
            ts=m.group("ts"), ip=m.group("ip"),
            data={"user": m.group("user"), "failed": failed}, raw=line))
    return out


def _parse_jsonl(text: str, source: str, kind: str) -> List[Event]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        out.append(Event(
            source=source, kind=kind, ts=str(d.get("ts", "")),
            ip=str(d.get("ip", "")), host=str(d.get("host", "")),
            data=d, raw=line))
    return out


def parse_nac(text: str) -> List[Event]:
    """NAC JSON lines: {ts, event, device_id, mac, ip, managed(bool), reason}."""
    return _parse_jsonl(text, "nac", "nac_event")


def parse_pms(text: str) -> List[Event]:
    """PMS JSON lines: {ts, event, asset_id, host, os, patched(bool), missing[...]}."""
    return _parse_jsonl(text, "pms", "pms_event")


# LureTrace export event -> normalized kind. Decoy kinds are deliberately separate
# from "request" and "auth_fail": they describe a fake service, not a real asset.
_LURETRACE_KINDS = {
    "ssh_auth": "decoy_auth",
    "http_login": "decoy_auth",
    "http_request": "decoy_request",
    "empty_connection": "decoy_connect",
    "protocol_anomaly": "decoy_anomaly",
}


def parse_luretrace(text: str) -> List[Event]:
    """LureTrace export JSON lines (GET /api/v1/export/events.jsonl):
    {ts, source, event, session_id, ip, port, protocol, username?,
     password_fingerprint?, method?, path?, user_agent?, status?}.
    Lines with an unknown event or an invalid IP are skipped."""
    out = []
    for e in _parse_jsonl(text, "luretrace", "decoy_event"):
        kind = _LURETRACE_KINDS.get(e.data.get("event"))
        if kind is None:
            continue
        try:
            ipaddress.ip_address(e.ip)
        except ValueError:
            continue
        e.kind = kind
        e.path = str(e.data.get("path") or "")
        e.ua = str(e.data.get("user_agent") or "")
        status = e.data.get("status")
        e.status = status if isinstance(status, int) else None
        out.append(e)
    return out


_DISPATCH = {
    "apache": parse_apache_access,
    "access": parse_apache_access,
    "error": parse_apache_error,
    "auth": parse_auth,
    "nac": parse_nac,
    "pms": parse_pms,
    "luretrace": parse_luretrace,
}


def load(path: str, kind: str, host: str = "") -> List[Event]:
    with open(path, "rb") as fh:
        text = fh.read().decode("utf-8", "replace")
    fn = _DISPATCH[kind]
    if kind in ("apache", "access", "error"):
        return fn(text, host=host)
    return fn(text)


def load_all(specs: Iterable[dict]) -> List[Event]:
    """specs: list of {path, kind, host?}. Returns all events concatenated."""
    events: List[Event] = []
    for s in specs:
        events.extend(load(s["path"], s["kind"], s.get("host", "")))
    return events
