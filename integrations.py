"""
Integration connectors to the NAC and PMS systems.

Each connector has a tiny, documented interface. Two implementations ship:
  * Mock*  — in-memory, for tests and the offline demo.
  * Http*  — talks to a REST endpoint; point it at the real NAC/PMS service.

REST contract the Http adapters assume (configure base URLs to match your
deployment / a thin shipper in front of NAC-dev and pms-server):
  NAC:  GET  {base}/device?ip=<ip>      -> {"ip":..,"managed":bool}
        POST {base}/quarantine          <- {"ip":..,"reason":..}  -> {"ok":bool}
  PMS:  GET  {base}/asset?host=<host>   -> {"host":..,"patched":bool,"missing":[..]}
        POST {base}/patch-jobs          <- {"host":..,"reason":..} -> {"ok":bool}
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request


def _get_json(url, timeout):
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except Exception:
        return {}


def _post_json(url, payload, timeout):
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "replace") or "{}")
    except Exception:
        return {}


# ---------------- Mock (offline) ----------------
class MockNac:
    def __init__(self, unmanaged=None):
        self._unmanaged = set(unmanaged or [])
        self.quarantined = []

    def device_status(self, ip):
        return {"ip": ip, "managed": ip not in self._unmanaged}

    def quarantine(self, ip, reason=""):
        self.quarantined.append((ip, reason))
        return True


class MockPms:
    def __init__(self, unpatched=None):
        self._unpatched = dict(unpatched or {})   # host -> [missing patches]
        self.patch_jobs = []

    def asset_status(self, host):
        return {"host": host, "patched": host not in self._unpatched,
                "missing": self._unpatched.get(host, [])}

    def request_patch(self, host, reason=""):
        self.patch_jobs.append((host, reason))
        return True


# ---------------- HTTP adapters ----------------
class HttpNac:
    def __init__(self, base, timeout=5.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def device_status(self, ip):
        return _get_json(f"{self.base}/device?ip={urllib.parse.quote(ip)}", self.timeout)

    def quarantine(self, ip, reason=""):
        return bool(_post_json(f"{self.base}/quarantine",
                               {"ip": ip, "reason": reason}, self.timeout).get("ok", False))


class HttpPms:
    def __init__(self, base, timeout=5.0):
        self.base = base.rstrip("/")
        self.timeout = timeout

    def asset_status(self, host):
        return _get_json(f"{self.base}/asset?host={urllib.parse.quote(host)}", self.timeout)

    def request_patch(self, host, reason=""):
        return bool(_post_json(f"{self.base}/patch-jobs",
                               {"host": host, "reason": reason}, self.timeout).get("ok", False))
