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

Correlation enriches alerts (device_managed / asset_patched) and raises
severity, and records the response action to take (NAC quarantine / PMS patch).
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


def analyze(events: List[Event], bf_threshold: int = 5, scan_threshold: int = 15) -> List[Alert]:
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

    return sort_alerts(alerts)
