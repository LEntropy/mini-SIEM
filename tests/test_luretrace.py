"""LureTrace integration: parsing the export and correlating decoy contacts."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sources                      # noqa: E402
from detect import analyze          # noqa: E402
from respond import respond         # noqa: E402
from report import build_report     # noqa: E402
from integrations import MockNac    # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "samples")
ATTACKER = "172.30.0.2"


def _line(event, ip=ATTACKER, **fields):
    return json.dumps({"ts": "2026-11-05T05:00:00Z", "source": "luretrace", "event": event,
                       "session_id": "s", "ip": ip, "port": 2222, "protocol": "ssh", **fields})


def _decoy(*lines):
    return sources.parse_luretrace("\n".join(lines))


def _auth(result, user="root", ip=ATTACKER):
    return sources.parse_auth(f"Nov  5 14:00:00 web01 sshd[1]: {result} password for {user} from {ip} port 1 ssh2")


def _web(path="/index.php", ip=ATTACKER, status=200):
    return sources.parse_apache_access(
        f'{ip} - - [05/Nov/2026:14:00:00 +0900] "GET {path} HTTP/1.1" {status} 10 "-" "Mozilla/5.0"', host="web01")


def _rules(alerts):
    return {a.rule_id: a for a in alerts}


def test_parser_maps_every_event():
    events = _decoy(_line("ssh_auth", username="root"), _line("http_login", username="admin"),
                    _line("http_request", path="/x", user_agent="ua", status=404),
                    _line("empty_connection"), _line("protocol_anomaly"))
    assert [e.kind for e in events] == ["decoy_auth", "decoy_auth", "decoy_request", "decoy_connect", "decoy_anomaly"]
    request = events[2]
    assert request.source == "luretrace" and request.path == "/x" and request.ua == "ua" and request.status == 404


def test_parser_skips_bad_lines():
    events = sources.parse_luretrace("\n".join([
        "not json",
        "[1, 2]",
        "42",
        _line("something_new"),
        _line("ssh_auth", ip="not-an-ip"),
        _line("ssh_auth", ip=""),
        _line("ssh_auth"),
    ]))
    assert len(events) == 1


def test_wrong_typed_fields_do_not_crash():
    events = _decoy(_line("http_request", path=123, user_agent=None, status="404", username=["x"]))
    alerts = analyze(events)
    assert events[0].path == "123" and events[0].ua == "" and events[0].status is None
    assert alerts


def test_sample_file_loads():
    events = sources.load(os.path.join(S, "luretrace.log"), "luretrace")
    assert {e.ip for e in events} == {"198.51.100.77", "203.0.113.9"}


def test_empty_connection_is_medium_without_response():
    alerts = analyze(_decoy(_line("empty_connection")))
    contact = _rules(alerts)["DECOY-CONTACT-001"]
    assert contact.severity == "medium" and contact.responses == []
    assert respond(alerts) == []


def test_credentials_on_decoy_are_high_and_plan_quarantine():
    alerts = analyze(_decoy(_line("ssh_auth", username="root")))
    contact = _rules(alerts)["DECOY-CONTACT-001"]
    assert contact.severity == "high" and contact.enrichment["decoy_usernames"] == ["root"]
    actions = respond(alerts)
    assert [(a.kind, a.target, a.status) for a in actions] == [("NAC.quarantine", ATTACKER, "planned")]


def test_attack_techniques_are_named():
    alerts = analyze(_decoy(_line("http_request", path="/index.php?id=1%27%20or%201=1", user_agent="sqlmap/1.8")))
    techniques = _rules(alerts)["DECOY-CONTACT-001"].enrichment["decoy_techniques"]
    assert "SQL Injection" in techniques and "Scanner tool" in techniques


def test_decoy_activity_is_not_treated_as_real_traffic():
    events = _decoy(*[_line("http_request", path="/.env", status=404)] * 20,
                    *[_line("ssh_auth", username="root")] * 6)
    rules = _rules(analyze(events))
    for real_rule in ("WEB-EXPOSE-001", "WEB-SCAN-001", "AUTH-BF-001"):
        assert real_rule not in rules, f"{real_rule} fired for decoy traffic"


def test_real_login_after_decoy_contact_is_critical():
    alerts = analyze(_decoy(_line("ssh_auth", username="root")) + _auth("Accepted"))
    alert = _rules(alerts)["DECOY-AUTH-001"]
    assert alert.severity == "critical" and alert.enrichment["decoy_reused_usernames"] == ["root"]
    assert any("quarantine" in r for r in alert.responses)


def test_real_login_from_other_ip_is_not_linked():
    rules = _rules(analyze(_decoy(_line("ssh_auth", username="root")) + _auth("Accepted", ip="10.0.0.5")))
    assert "DECOY-AUTH-001" not in rules and "DECOY-PIVOT-001" not in rules


def test_real_traffic_without_login_is_pivot():
    alerts = analyze(_decoy(_line("empty_connection")) + _web())
    alert = _rules(alerts)["DECOY-PIVOT-001"]
    assert alert.severity == "high" and alert.host == "web01"
    assert [a.target for a in respond(alerts)] == [ATTACKER]


def test_existing_alert_is_raised_but_recon_is_not():
    events = _decoy(_line("empty_connection")) + _web(path="/a?q=union select 1", status=404)
    without = _rules(analyze(_web(path="/a?q=union select 1", status=404)))["WEB-SQLI-001"]
    with_decoy = _rules(analyze(events))["WEB-SQLI-001"]
    assert without.severity == "high" and with_decoy.severity == "critical"
    assert with_decoy.enrichment["decoy_contact"] is True

    scanner = sources.parse_apache_access(
        f'{ATTACKER} - - [05/Nov/2026:14:00:00 +0900] "GET / HTTP/1.1" 200 1 "-" "nikto"')
    recon = _rules(analyze(_decoy(_line("empty_connection")) + scanner))["WEB-SCANUA-001"]
    assert recon.severity == "medium"


def test_brute_force_on_real_server_is_raised():
    fails = [e for _ in range(5) for e in _auth("Failed")]
    alert = _rules(analyze(_decoy(_line("empty_connection")) + fails))["AUTH-BF-001"]
    assert alert.severity == "critical"


def test_trusted_source_is_ignored():
    events = _decoy(_line("ssh_auth", username="root")) + _auth("Accepted")
    alerts = analyze(events, trusted_decoy_ips=[ATTACKER])
    assert not [a for a in alerts if a.rule_id.startswith("DECOY-")]
    assert respond(alerts) == []


def test_no_decoy_data_changes_nothing():
    assert analyze(_web()) == []


def test_execute_calls_nac_once():
    nac = MockNac()
    alerts = analyze(_decoy(_line("ssh_auth", username="root")) + _auth("Accepted"))
    actions = respond(alerts, nac=nac, execute=True)
    assert [t[0] for t in nac.quarantined] == [ATTACKER]
    assert [a.status for a in actions] == ["executed"]


def test_report_escapes_attacker_text():
    payload = "<script>alert(1)</script>"
    events = _decoy(_line("ssh_auth", username=payload), _line("http_request", path="/x", user_agent="<img src=x onerror=alert(1)>"))
    html = build_report(analyze(events), actions=[], events=events, target="t")
    assert payload not in html and "<img src=x" not in html
    assert "미끼(LureTrace)" in html and "LureTrace: 미끼 접촉" in html


def test_alerts_are_json_serializable():
    alerts = analyze(_decoy(_line("ssh_auth", username="root")))
    json.dumps([a.as_dict() for a in alerts])


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
