"""Detection + cross-source correlation tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sources            # noqa: E402
from detect import analyze  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "samples")

ATTACK = [
    {"path": os.path.join(S, "access.log"), "kind": "apache", "host": "web01"},
    {"path": os.path.join(S, "auth.log"), "kind": "auth"},
    {"path": os.path.join(S, "nac.log"), "kind": "nac"},
    {"path": os.path.join(S, "pms.log"), "kind": "pms"},
]
BENIGN = [
    {"path": os.path.join(S, "benign", "access.log"), "kind": "apache", "host": "web01"},
    {"path": os.path.join(S, "benign", "auth.log"), "kind": "auth"},
]


def _alerts(specs):
    return analyze(sources.load_all(specs))


def test_all_attack_categories_detected():
    cats = {a.category for a in _alerts(ATTACK)}
    for expected in ("SQL Injection", "Cross-Site Scripting", "Path Traversal / LFI",
                     "Webshell / Command Injection", "Sensitive File Access",
                     "Reconnaissance", "Brute Force"):
        assert expected in cats, f"{expected} not detected; got {cats}"


def test_nac_correlation_marks_unmanaged_and_quarantines():
    hits = [a for a in _alerts(ATTACK)
            if a.src_ip == "203.0.113.9" and a.enrichment.get("device_managed") is False]
    assert hits, "attacker IP should be correlated with NAC unmanaged status"
    assert any("NAC: quarantine" in r for a in hits for r in a.responses)


def test_pms_correlation_escalates_unpatched_host():
    # exploitation of the unpatched host must escalate to critical + patch action
    crit = [a for a in _alerts(ATTACK)
            if a.host == "web01" and a.category == "SQL Injection"]
    assert crit and all(a.severity == "critical" for a in crit)
    assert all(a.enrichment.get("asset_patched") is False for a in crit)
    assert any("PMS: trigger patch" in r for a in crit for r in a.responses)


def test_bruteforce_detected():
    bf = [a for a in _alerts(ATTACK) if a.rule_id == "AUTH-BF-001"]
    assert bf and bf[0].severity == "critical"  # unmanaged → escalated


def test_benign_is_quiet():
    high = [a for a in _alerts(BENIGN) if a.severity in ("critical", "high")]
    assert not high, "benign logs must not raise critical/high: " + \
        "; ".join(f"{a.rule_id} {a.src_ip}" for a in high)


if __name__ == "__main__":
    ok = True
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS {name}")
            except AssertionError as e:
                ok = False; print(f"FAIL {name}: {e}")
    print("ALL PASS" if ok else "FAILURES")
    sys.exit(0 if ok else 1)
