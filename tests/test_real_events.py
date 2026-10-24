# tests on events that were recorded by a real aws account (cleaned by tools/sanitize_live_events.py)
from collections import Counter
from pathlib import Path

from detections.matcher import load_events, load_rules, scan

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "cloudtrail_real" / "real-events.json"
RULES = ROOT / "detections" / "sigma"


def hits():
    events = load_events(str(FIXTURE))
    return events, scan(load_rules(str(RULES)), events)


def test_fixture_has_no_real_account_data():
    text = FIXTURE.read_text(encoding="utf-8")
    assert "837465732902" not in text
    assert "AKIA" not in text and "ASIA" not in text


def test_each_attack_fires_its_rule_on_a_real_event():
    events, found = hits()
    by_rule = Counter(title for title, _id, _e in found)
    assert by_rule["AWS IAM Policy Version Created And Set As Default"] == 1
    assert by_rule["AWS IAM Policy Default Version Changed"] == 1
    assert by_rule["AWS IAM Admin Policy Attached To User Role Or Group"] == 1
    assert by_rule["AWS IAM Inline Admin Policy Written"] == 1
    assert by_rule["AWS IAM Role Trust Policy Changed"] == 1
    # dave, the assumed role in the chain, and the admin who made keys for others
    assert by_rule["AWS IAM Access Key Created For A Different User"] == 3
    assert len(found) == 8


def test_chain_is_caught_when_the_caller_is_an_assumed_role():
    _events, found = hits()
    callers = [e["userIdentity"]["arn"] for title, _i, e in found if e["eventName"] == "CreateAccessKey"]
    assert any("assumed-role/key-manager-role" in c for c in callers)


def test_benign_events_stay_quiet():
    events, found = hits()
    fired = {id(e) for _t, _i, e in found}
    for e in events:
        # bob attaching ReadOnlyAccess, pete writing a harmless inline policy
        p = e.get("requestParameters") or {}
        if p.get("policyArn", "").endswith("ReadOnlyAccess") or p.get("policyName") == "benign":
            assert id(e) not in fired


def test_denied_calls_have_no_request_parameters_so_field_rules_cannot_fire():
    # real finding: a denied call is logged without requestParameters, so these rules miss attempts
    events, found = hits()
    fired = {id(e) for _t, _i, e in found}
    denied = [e for e in events if e.get("errorCode") == "AccessDenied"]
    assert denied, "the fixture should contain denied calls"
    for e in denied:
        assert not e.get("requestParameters")
        assert id(e) not in fired