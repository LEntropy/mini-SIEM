"""Report smoke test."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sources                      # noqa: E402
from detect import analyze          # noqa: E402
from respond import respond         # noqa: E402
from report import build_report     # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "samples")


def test_report_contains_sections_and_actions():
    events = sources.load_all([
        {"path": os.path.join(S, "access.log"), "kind": "apache", "host": "web01"},
        {"path": os.path.join(S, "auth.log"), "kind": "auth"},
        {"path": os.path.join(S, "nac.log"), "kind": "nac"},
        {"path": os.path.join(S, "pms.log"), "kind": "pms"},
    ])
    alerts = analyze(events)
    actions = respond(alerts, execute=False)
    h = build_report(alerts, actions=actions, events=events, target="web01")
    assert "위협 탐지 리포트" in h
    assert "대응 조치" in h and "NAC.quarantine" in h and "PMS.request_patch" in h
    assert "미관리 디바이스" in h and "미패치" in h
    assert "web01" in h


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
