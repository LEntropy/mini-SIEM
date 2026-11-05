#!/usr/bin/env python3
"""One-command demo: analyze the bundled multi-source sample logs (web + auth +
NAC + PMS), correlate, plan response actions, and write the Korean report.
No external services needed."""
import os
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sources
from detect import analyze
from respond import respond
from report import write_report

S = os.path.join(HERE, "samples")


def main():
    events = sources.load_all([
        {"path": os.path.join(S, "access.log"), "kind": "apache", "host": "web01"},
        {"path": os.path.join(S, "auth.log"), "kind": "auth"},
        {"path": os.path.join(S, "nac.log"), "kind": "nac"},
        {"path": os.path.join(S, "pms.log"), "kind": "pms"},
        {"path": os.path.join(S, "luretrace.log"), "kind": "luretrace"},
    ])
    alerts = analyze(events)
    actions = respond(alerts, execute=False)      # plan only
    out = os.environ.get("OUT", os.path.join(HERE, "docs", "sample_report.html"))
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    write_report(alerts, out, actions=actions, events=events, target="web01 (demo)")
    print("report:", out,
          "| events:", len(events),
          "| alerts:", dict(Counter(a.severity for a in alerts)),
          "| planned actions:", len(actions))


if __name__ == "__main__":
    main()
