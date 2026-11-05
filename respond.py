"""
Response engine (SOAR-style).

Turns correlated alerts into containment/remediation actions via the NAC and
PMS connectors. SAFE BY DEFAULT: with execute=False it only *plans* actions;
pass execute=True (CLI --respond) to actually call the connectors.

Actions:
  * NAC.quarantine     — high/critical alert from an unmanaged device (NAC) or a
                         source that touched a decoy (LureTrace)
  * PMS.request_patch  — critical exploitation against an unpatched asset (PMS)
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List


@dataclass
class Action:
    kind: str        # NAC.quarantine | PMS.request_patch
    target: str      # ip or host
    reason: str
    status: str      # planned | executed | failed

    def as_dict(self):
        return asdict(self)


def respond(alerts, nac=None, pms=None, execute=False) -> List[Action]:
    actions: List[Action] = []
    seen = set()
    for a in alerts:
        if a.severity not in ("high", "critical"):
            continue

        # Containment: quarantine an unmanaged hostile source, or one that touched a decoy, via NAC
        if a.src_ip and (a.enrichment.get("device_managed") is False or a.enrichment.get("decoy_contact")):
            key = ("nac", a.src_ip)
            if key not in seen:
                seen.add(key)
                status = "planned"
                if execute and nac is not None:
                    try:
                        status = "executed" if nac.quarantine(a.src_ip, a.category) else "failed"
                    except Exception:
                        status = "failed"
                actions.append(Action("NAC.quarantine", a.src_ip, a.category, status))

        # Remediation: patch an exploited unpatched asset via PMS
        if a.host and a.severity == "critical" and a.enrichment.get("asset_patched") is False:
            key = ("pms", a.host)
            if key not in seen:
                seen.add(key)
                status = "planned"
                reason = ", ".join(a.enrichment.get("missing_patches", [])) or a.category
                if execute and pms is not None:
                    try:
                        status = "executed" if pms.request_patch(a.host, reason) else "failed"
                    except Exception:
                        status = "failed"
                actions.append(Action("PMS.request_patch", a.host, reason, status))

    return actions
