#!/usr/bin/env python3
"""
LogSentry — multi-source log threat detection with NAC/PMS correlation & response.

  python sentry.py analyze \
      --access samples/access.log --host web01 \
      --auth samples/auth.log --nac samples/nac.log --pms samples/pms.log \
      --out report.html

Options:
  --respond                actually execute response actions (default: plan only)
  --nac-url / --pms-url    REST endpoints for execution (else offline mocks)
  --json                   print alerts as JSON instead of a summary

Standard library only.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sources                                    # noqa: E402
from detect import analyze                        # noqa: E402
from respond import respond                       # noqa: E402
from report import write_report                   # noqa: E402
from integrations import MockNac, MockPms, HttpNac, HttpPms  # noqa: E402


def _build_specs(args):
    specs = []
    if args.access:
        specs.append({"path": args.access, "kind": "apache", "host": args.host or ""})
    if args.error:
        specs.append({"path": args.error, "kind": "error", "host": args.host or ""})
    if args.auth:
        specs.append({"path": args.auth, "kind": "auth"})
    if args.nac:
        specs.append({"path": args.nac, "kind": "nac"})
    if args.pms:
        specs.append({"path": args.pms, "kind": "pms"})
    return specs


def _connectors(args, events):
    nac = HttpNac(args.nac_url) if args.nac_url else \
        MockNac(unmanaged=[e.ip for e in events
                           if e.source == "nac" and e.data.get("managed") is False and e.ip])
    pms = HttpPms(args.pms_url) if args.pms_url else \
        MockPms(unpatched={e.host: e.data.get("missing", []) for e in events
                           if e.source == "pms" and e.data.get("event") == "inventory"
                           and e.data.get("patched") is False and e.host})
    return nac, pms


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sentry")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("--access"); a.add_argument("--error")
    a.add_argument("--auth"); a.add_argument("--nac"); a.add_argument("--pms")
    a.add_argument("--host", default="")
    a.add_argument("--out")
    a.add_argument("--respond", action="store_true")
    a.add_argument("--nac-url"); a.add_argument("--pms-url")
    a.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    events = sources.load_all(_build_specs(args))
    alerts = analyze(events)

    nac, pms = _connectors(args, events)
    actions = respond(alerts, nac=nac, pms=pms, execute=args.respond)

    if args.out:
        tgt = args.host or (args.access or "(미지정)")
        write_report(alerts, args.out, actions=actions, events=events, target=tgt)
        print(f"report written: {args.out}")

    if args.json:
        print(json.dumps({"alerts": [x.as_dict() for x in alerts],
                          "actions": [x.as_dict() for x in actions]},
                         ensure_ascii=False, indent=2))
    else:
        from collections import Counter
        c = Counter(x.severity for x in alerts)
        print("events:", len(events), "| alerts:", dict(c), "| actions:",
              f"{len(actions)} ({'executed' if args.respond else 'planned'})")
        for x in alerts:
            if x.severity in ("critical", "high"):
                print(f"  [{x.severity.upper():8}] {x.rule_id} {x.src_ip or '-':15} {x.category}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
