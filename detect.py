"""
Detection engine.

Two layers:
  1. Signature detection on individual web requests (SQLi, XSS, traversal,
     webshell/RCE, sensitive-file access, scanner user-agents).
  2. Cross-source correlation — the part that makes this more than a grep:
       * brute force       (auth log)
       * endpoint scanning (4xx bursts)
       * UNMANAGED-DEVICE attack : attacker IP that NAC flagged managed=false
       * UNPATCHED-ASSET attack  : web attack against a host PMS marks patched=false
       * successful exploitation : signature hit that returned HTTP 200
       * decoy contact           : source that touched a LureTrace decoy, weighted
                                   by what it did there and on real services

Correlation enriches alerts (device_managed / asset_patched / decoy_contact) and
raises severity, and records the response action to take (NAC quarantine / PMS patch).
"""
from __future__ import annotations

import re
import urllib.parse
from collections import defaultdict
from typing import List

from core import Event, Alert, sort_alerts

LEVELS = ["info", "low", "medium", "high", "critical"]


def _raise(sev, n=1):
    return LEVELS[min(len(LEVELS) - 1, LEVELS.index(sev) + n)]


SIGNATURES = [
    ("WEB-SQLI-001", "high", "SQL Injection", "CWE-89",
     re.compile(r"union\s+select|\bor\s+1=1\b|'\s*or\s*'?1'?\s*=\s*'?1|sleep\(|benchmark\(|information_schema|xp_cmdshell|\bunion\b[^#]*\bselect\b", re.I),
     "SQL injection payload observed in request.",
     "Use prepared statements; reject/cast unexpected input."),
    ("WEB-XSS-001", "medium", "Cross-Site Scripting", "CWE-79",
     re.compile(r"<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+onerror|alert\(", re.I),
     "Cross-site scripting payload observed in request.",
     "HTML-encode all reflected output (ENT_QUOTES)."),
    ("WEB-LFI-001", "high", "Path Traversal / LFI", "CWE-22",
     re.compile(r"\.\./|\.\.%2f|/etc/passwd|php://|/proc/self", re.I),
     "Path traversal / local file inclusion attempt.",
     "Normalize and confine file paths to an allowed directory."),
    ("WEB-RCE-001", "critical", "Webshell / Command Injection", "CWE-94",
     re.compile(r"/uploads/[^ ]*\.php|[?&]cmd=|/shell\.php|\bc99\b|\br57\b|eval\(|base64_decode\(", re.I),
     "Webshell / command-execution attempt.",
     "Forbid PHP execution in upload dirs; validate inputs."),
    ("WEB-EXPOSE-001", "medium", "Sensitive File Access", "CWE-538",
     re.compile(r"/\.git|/\.env|htdocs\.zip|/wp-config|\.bak(\b|$)|/phpmyadmin|/\.ssh|backup\.(zip|sql)|\bdb\.sql\b", re.I),
     "Access attempt to a sensitive/backup/config path.",
     "Remove such files from the webroot; block these paths."),
]
SCANNER_UA = re.compile(
    r"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|nuclei|wpscan|acunetix|hydra|wfuzz|zgrab", re.I)
_SUCCESS_CATS = {"SQL Injection", "Webshell / Command Injection",
                 "Path Traversal / LFI", "Sensitive File Access"}


def detect_signatures(events: List[Event]) -> List[Alert]:
    alerts: List[Alert] = []
    scanner_seen = set()
    for e in events:
        if e.kind != "request":
            continue
        hay = urllib.parse.unquote(e.raw or e.path).lower()
        for rid, sev, cat, cwe, rx, msg, rec in SIGNATURES:
            if rx.search(hay):
                s = sev
                if e.status == 200 and cat in _SUCCESS_CATS:
                    s = _raise(sev)
                a = Alert(rid, s, cat, cwe, msg, src_ip=e.ip, host=e.host,
                          when=e.ts, evidence=(e.path or e.raw)[:200], recommendation=rec)
                if e.status == 200 and cat in _SUCCESS_CATS:
                    a.enrichment["http_status"] = 200
                    a.message += " Server returned HTTP 200 — possible success."
                alerts.append(a)
        if e.ua and SCANNER_UA.search(e.ua) and e.ip not in scanner_seen:
            scanner_seen.add(e.ip)
            alerts.append(Alert(
                "WEB-SCANUA-001", "medium", "Reconnaissance", "ATT&CK-T1595",
                f"Automated scanning tool user-agent from {e.ip}.",
                src_ip=e.ip, host=e.host, when=e.ts, evidence=e.ua[:120],
                recommendation="Block/limit automated scanners; investigate the source."))
    return alerts


def _decoy_contacts(events: List[Event], trusted) -> dict:
    """Summarize decoy activity per source IP, leaving out trusted sources."""
    contacts = {}
    for e in events:
        if e.source != "luretrace" or e.ip in trusted:
            continue
        c = contacts.setdefault(e.ip, {"events": 0, "credentials": 0, "users": set(),
                                       "techniques": set(), "first": e.ts})
        c["events"] += 1
        if e.kind == "decoy_auth":
            c["credentials"] += 1
            if e.data.get("username"):
                c["users"].add(str(e.data["username"]))
        hay = urllib.parse.unquote(e.path).lower() + " " + e.ua.lower()
        for _rid, _sev, category, _cwe, rx, _msg, _rec in SIGNATURES:
            if rx.search(hay):
                c["techniques"].add(category)
        if SCANNER_UA.search(e.ua):
            c["techniques"].add("Scanner tool")
    return contacts


def correlate_decoys(events: List[Event], alerts: List[Alert], trusted=()) -> List[Alert]:
    """Cross-reference decoy contacts with real logs.

    Nothing legitimate should ever touch a decoy, so a contact is a strong signal
    on its own, and it raises the weight of whatever else that source did. This
    enriches `alerts` in place and returns the new alerts. Syslog timestamps have
    no year or zone, so "also seen" means the same logs, not a proven order.
    """
    contacts = _decoy_contacts(events, set(trusted))
    new_alerts: List[Alert] = []

    for ip, c in contacts.items():
        serious = c["credentials"] > 0 or bool(c["techniques"])
        a = Alert(
            "DECOY-CONTACT-001", "high" if serious else "medium", "Deception Contact",
            "ATT&CK-T1110" if c["credentials"] else "ATT&CK-T1595",
            f"{ip} touched the LureTrace decoy: {c['events']} events, "
            f"{c['credentials']} credential attempts.",
            src_ip=ip, when=c["first"],
            evidence="users=" + ",".join(sorted(c["users"]))[:120] +
                     " techniques=" + ",".join(sorted(c["techniques"]))[:120],
            recommendation="Investigate the source; legitimate users have no reason to reach a decoy.")
        a.enrichment.update(decoy_contact=True, decoy_events=c["events"],
                            decoy_usernames=sorted(c["users"]),
                            decoy_techniques=sorted(c["techniques"]))
        if serious:
            a.responses.append(f"NAC: quarantine {ip} (touched decoy)")
        new_alerts.append(a)

    # Real logins and traffic from an address that also touched the decoy.
    real = defaultdict(list)
    for e in events:
        if e.source in ("apache", "auth") and e.ip in contacts:
            real[e.ip].append(e)
    for ip, evs in real.items():
        c = contacts[ip]
        logins = [e for e in evs if e.kind == "auth_ok"]
        if logins:
            users = sorted({str(e.data.get("user", "")) for e in logins})
            reused = sorted(set(users) & c["users"])
            a = Alert(
                "DECOY-AUTH-001", "critical", "Compromise After Decoy Contact", "ATT&CK-T1078",
                f"{ip} logged in to a real server and also touched the decoy.",
                src_ip=ip, when=logins[0].ts,
                evidence="real login users=" + ",".join(users)[:120] +
                         " also tried on decoy=" + ",".join(reused)[:120],
                recommendation="Treat the account as compromised: end its sessions and reset its credentials.")
            a.enrichment.update(decoy_contact=True, decoy_reused_usernames=reused)
            a.responses.append(f"NAC: quarantine {ip} (touched decoy)")
        else:
            a = Alert(
                "DECOY-PIVOT-001", "high", "Activity After Decoy Contact", "ATT&CK-T1021",
                f"{ip} touched the decoy and also reached real services ({len(evs)} events).",
                src_ip=ip, host=evs[0].host, when=evs[0].ts,
                evidence=f"{len(evs)} events in real logs, {c['events']} on the decoy",
                recommendation="Review this source's activity on the real services.")
            a.enrichment["decoy_contact"] = True
            a.responses.append(f"NAC: quarantine {ip} (touched decoy)")
        new_alerts.append(a)

    # Existing alerts from these sources carry more weight, except reconnaissance noise.
    for a in alerts:
        if a.src_ip in contacts:
            a.enrichment["decoy_contact"] = True
            if a.category != "Reconnaissance":
                a.severity = _raise(a.severity)
    return new_alerts


def analyze(events: List[Event], bf_threshold: int = 5, scan_threshold: int = 15,
            trusted_decoy_ips=()) -> List[Alert]:
    alerts = detect_signatures(events)

    # context from NAC / PMS
    nac_unmanaged = {e.ip for e in events
                     if e.source == "nac" and e.data.get("managed") is False and e.ip}
    pms_unpatched = {e.host: e.data.get("missing", [])
                     for e in events
                     if e.source == "pms" and e.data.get("event") == "inventory"
                     and e.data.get("patched") is False and e.host}

    recon_cats = {"Reconnaissance"}
    exploit_cats = {"SQL Injection", "Webshell / Command Injection", "Path Traversal / LFI"}

    # enrich signature alerts with NAC/PMS correlation
    for a in alerts:
        if a.src_ip and a.src_ip in nac_unmanaged:
            a.enrichment["device_managed"] = False
            if a.category not in recon_cats:          # don't over-escalate recon noise
                a.severity = _raise(a.severity)
            a.responses.append(f"NAC: quarantine {a.src_ip} (unmanaged device)")
        if a.host and a.host in pms_unpatched:
            a.enrichment["asset_patched"] = False
            a.enrichment["missing_patches"] = pms_unpatched[a.host]
            # Escalate to critical only for genuine exploitation of the unpatched host,
            # not for failed recon/404 probes.
            severe = a.category in exploit_cats or \
                (a.enrichment.get("http_status") == 200 and a.category == "Sensitive File Access")
            if severe:
                a.severity = "critical"
                miss = ", ".join(pms_unpatched[a.host]) or "pending patches"
                a.responses.append(f"PMS: trigger patch on {a.host} ({miss})")

    # brute force (auth log)
    fails = defaultdict(list)
    for e in events:
        if e.kind == "auth_fail":
            fails[e.ip].append(e)
    for ip, evs in fails.items():
        if len(evs) >= bf_threshold:
            a = Alert("AUTH-BF-001", "high", "Brute Force", "ATT&CK-T1110",
                      f"SSH brute force: {len(evs)} failed logins from {ip}.",
                      src_ip=ip, when=evs[0].ts,
                      evidence=f"{len(evs)} failed password events",
                      recommendation="Lock the source; enforce key-only auth + fail2ban.")
            if ip in nac_unmanaged:
                a.enrichment["device_managed"] = False
                a.severity = "critical"
                a.responses.append(f"NAC: quarantine {ip} (unmanaged device)")
            alerts.append(a)

    # endpoint scanning (4xx bursts)
    errs = defaultdict(int)
    for e in events:
        if e.source == "apache" and e.status and 400 <= e.status < 500:
            errs[e.ip] += 1
    for ip, c in errs.items():
        if c >= scan_threshold:
            alerts.append(Alert(
                "WEB-SCAN-001", "medium", "Reconnaissance", "ATT&CK-T1595",
                f"Endpoint/directory scanning: {c} 4xx responses from {ip}.",
                src_ip=ip, evidence=f"{c} 4xx responses",
                recommendation="Rate-limit and block the scanning source."))

    alerts.extend(correlate_decoys(events, alerts, trusted_decoy_ips))
    return sort_alerts(alerts)
