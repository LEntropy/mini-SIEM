"""Parser tests: each source normalizes into core.Event with the right fields."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sources  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.path.join(ROOT, "samples")


def test_apache_access_parses_fields():
    evs = sources.load(os.path.join(S, "access.log"), "apache", host="web01")
    assert evs, "no access events parsed"
    e = evs[0]
    assert e.source == "apache" and e.kind == "request"
    assert e.ip == "10.0.0.5" and e.status == 200 and e.host == "web01"
    assert e.path.startswith("/index.php")
    # the sqlmap request is present with its UA
    assert any("sqlmap" in x.ua.lower() for x in evs)


def test_auth_detects_failed_and_ok():
    evs = sources.load(os.path.join(S, "auth.log"), "auth")
    fails = [e for e in evs if e.kind == "auth_fail"]
    oks = [e for e in evs if e.kind == "auth_ok"]
    assert len(fails) >= 5 and oks, "auth parsing wrong"
    assert all(e.ip for e in fails)


def test_nac_and_pms_jsonl():
    nac = sources.load(os.path.join(S, "nac.log"), "nac")
    pms = sources.load(os.path.join(S, "pms.log"), "pms")
    assert any(e.data.get("managed") is False and e.ip == "203.0.113.9" for e in nac)
    assert any(e.data.get("patched") is False and e.host == "web01" for e in pms)


def test_load_all_concatenates():
    evs = sources.load_all([
        {"path": os.path.join(S, "access.log"), "kind": "apache", "host": "web01"},
        {"path": os.path.join(S, "auth.log"), "kind": "auth"},
        {"path": os.path.join(S, "nac.log"), "kind": "nac"},
        {"path": os.path.join(S, "pms.log"), "kind": "pms"},
    ])
    srcs = {e.source for e in evs}
    assert srcs == {"apache", "auth", "nac", "pms"}


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
