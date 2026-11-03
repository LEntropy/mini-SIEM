"""Response-engine tests: planning (dry-run) and execution via mock connectors."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sources                      # noqa: E402
from detect import analyze          # noqa: E402
from respond import respond         # noqa: E402
from integrations import MockNac, MockPms  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "samples")
ATTACK = [
    {"path": os.path.join(S, "access.log"), "kind": "apache", "host": "web01"},
    {"path": os.path.join(S, "auth.log"), "kind": "auth"},
    {"path": os.path.join(S, "nac.log"), "kind": "nac"},
    {"path": os.path.join(S, "pms.log"), "kind": "pms"},
]


def _alerts():
    return analyze(sources.load_all(ATTACK))


def test_dry_run_plans_but_does_not_execute():
    nac, pms = MockNac(unmanaged=["203.0.113.9"]), MockPms(unpatched={"web01": ["CVE-x"]})
    actions = respond(_alerts(), nac, pms, execute=False)
    assert any(a.kind == "NAC.quarantine" and a.target == "203.0.113.9" for a in actions)
    assert any(a.kind == "PMS.request_patch" and a.target == "web01" for a in actions)
    assert all(a.status == "planned" for a in actions)
    assert nac.quarantined == [] and pms.patch_jobs == []  # nothing actually called


def test_execute_calls_connectors_once_each():
    nac, pms = MockNac(unmanaged=["203.0.113.9"]), MockPms(unpatched={"web01": ["CVE-x"]})
    actions = respond(_alerts(), nac, pms, execute=True)
    assert [t[0] for t in nac.quarantined] == ["203.0.113.9"]      # deduped to one
    assert [t[0] for t in pms.patch_jobs] == ["web01"]
    assert all(a.status == "executed" for a in actions)


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
