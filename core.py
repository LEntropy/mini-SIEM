"""Shared models for LogSentry: a normalized log Event and a detection Alert."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Event:
    """A single log line normalized across all sources (apache/auth/nac/pms)."""
    source: str                      # apache | auth | nac | pms | luretrace
    kind: str                        # request | php_error | auth_fail | nac_event | pms_event | decoy_*
    ts: str = ""                     # ISO-ish timestamp string
    ip: str = ""                     # source IP (attacker / client / device)
    host: str = ""                   # target host / asset (when known)
    status: Optional[int] = None     # HTTP status for requests
    path: str = ""                   # request path+query (apache)
    ua: str = ""                     # user agent (apache)
    data: dict = field(default_factory=dict)   # source-specific fields
    raw: str = ""

    def as_dict(self):
        return asdict(self)


@dataclass
class Alert:
    rule_id: str
    severity: str                    # critical|high|medium|low|info
    category: str
    technique: str                   # CWE / ATT&CK-ish tag
    message: str
    src_ip: str = ""
    host: str = ""
    when: str = ""
    evidence: str = ""
    recommendation: str = ""
    enrichment: dict = field(default_factory=dict)   # e.g. {"asset_patched":False}
    responses: list = field(default_factory=list)    # response actions taken/suggested

    def as_dict(self):
        return asdict(self)


def sort_alerts(alerts):
    return sorted(alerts, key=lambda a: (SEVERITY_RANK.get(a.severity, 9), a.src_ip, a.when))
