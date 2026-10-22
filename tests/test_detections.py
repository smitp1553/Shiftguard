import json
import uuid
from pathlib import Path

import pytest
import yaml

from detections.matcher import (
    Condition,
    field_matches,
    get_field,
    load_events,
    load_rules,
    rule_matches,
    scan,
    value_matches,
    wildcard_to_regex,
)

ROOT = Path(__file__).parent.parent
RULES_DIR = ROOT / "detections" / "sigma"
FIXTURES = ROOT / "tests" / "fixtures" / "cloudtrail"

RULE_FILES = sorted(RULES_DIR.glob("*.yml"))
RULE_NAMES = [p.stem for p in RULE_FILES]


def rule_of(name):
    return yaml.safe_load((RULES_DIR / f"{name}.yml").read_text(encoding="utf-8"))


def fixture_of(name):
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


# ---- the rule files themselves ----

def test_there_are_at_least_eight_rules():
    assert len(RULE_FILES) >= 8


@pytest.mark.parametrize("name", RULE_NAMES)
def test_rule_has_the_fields_we_promise(name):
    rule = rule_of(name)
    for key in ["title", "id", "description", "tags", "logsource", "detection", "falsepositives", "level"]:
        assert rule.get(key), f"{name} has no {key}"
    uuid.UUID(rule["id"])  # must be a real uuid
    assert rule["level"] in ("low", "medium", "high", "critical")
    assert rule["logsource"] == {"product": "aws", "service": "cloudtrail"}
    assert any(t.startswith("attack.t1") for t in rule["tags"]), "needs an ATT&CK technique tag"


def test_rule_ids_are_unique():
    ids = [rule_of(n)["id"] for n in RULE_NAMES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("name", RULE_NAMES)
def test_every_rule_has_a_fixture_file(name):
    assert (FIXTURES / f"{name}.json").exists()


# ---- every rule fires on the malicious events and stays quiet on the benign ones ----

@pytest.mark.parametrize("name", RULE_NAMES)
def test_rule_fires_on_malicious_events(name):
    rule = rule_of(name)
    for event in fixture_of(name)["malicious"]:
        assert rule_matches(rule, event), f"{name} did not fire on {event['eventName']}"


@pytest.mark.parametrize("name", RULE_NAMES)
def test_rule_stays_quiet_on_benign_events(name):
    rule = rule_of(name)
    for event in fixture_of(name)["benign"]:
        assert not rule_matches(rule, event), f"{name} fired on benign {event['eventName']}"


def test_no_rule_fires_on_any_benign_event():
    # stronger than the test above: not even another rule may react to a benign event
    rules = load_rules(RULES_DIR)
    benign = [e for n in RULE_NAMES for e in fixture_of(n)["benign"]]
    assert scan(rules, benign) == []


def test_scan_reports_rule_title_and_id():
    rules = load_rules(RULES_DIR)
    events = fixture_of("aws_iam_create_policy_version")["malicious"]
    hits = scan(rules, events)
    assert len(hits) >= 1
    title, rule_id, event = hits[0]
    assert title == "AWS IAM Policy Version Created And Set As Default"
    assert rule_id == rule_of("aws_iam_create_policy_version")["id"]


def test_load_events_reads_a_real_cloudtrail_file(tmp_path):
    path = tmp_path / "log.json"
    path.write_text(json.dumps({"Records": [{"eventName": "StopLogging"}]}))
    assert load_events(path) == [{"eventName": "StopLogging"}]


def test_load_events_reads_a_list_one_event_per_line_and_a_single_event(tmp_path):
    lines = tmp_path / "lines.json"
    lines.write_text('{"eventName": "A"}\n{"eventName": "B"}\n')
    assert [e["eventName"] for e in load_events(lines)] == ["A", "B"]

    single = tmp_path / "single.json"
    single.write_text('{"eventName": "A"}')
    assert load_events(single) == [{"eventName": "A"}]

    plain = tmp_path / "plain.json"
    plain.write_text('[{"eventName": "A"}]')
    assert load_events(plain) == [{"eventName": "A"}]


# ---- the matcher itself ----

def test_get_field_follows_dots_and_returns_none_when_missing():
    event = {"a": {"b": {"c": 5}}}
    assert get_field(event, "a.b.c") == 5
    assert get_field(event, "a.x.c") is None
    assert get_field(event, "z") is None


def test_text_matching_ignores_case_and_booleans_work():
    assert value_matches("CreatePolicyVersion", "createpolicyversion", [])
    assert value_matches(True, True, [])
    assert not value_matches(False, True, [])


def test_wildcards_and_escaped_star():
    assert value_matches("abcdef", "abc*", [])
    assert value_matches("abc", "a?c", [])
    assert not value_matches("abbc", "a?c", [])
    # an escaped star is a real star, not a wildcard
    assert value_matches('"Action":"*"', r'"Action":"\*"', ["contains"])
    assert not value_matches('"Action":"s3:Get"', r'"Action":"\*"', ["contains"])
    assert wildcard_to_regex("a.b") == r"a\.b"


def test_contains_startswith_endswith():
    assert value_matches("x:policy/AdministratorAccess", ":policy/AdministratorAccess", ["endswith"])
    assert not value_matches("x:policy/AdministratorAccess-Amplify", ":policy/AdministratorAccess", ["endswith"])
    assert value_matches("arn:aws:iam", "arn:", ["startswith"])
    assert value_matches("arn:aws:iam", ":aws:", ["contains"])


def test_a_list_of_values_means_or_and_all_means_and():
    event = {"name": "hello world"}
    assert field_matches(event, "name|contains", ["nope", "hello"])
    assert not field_matches(event, "name|contains|all", ["nope", "hello"])
    assert field_matches(event, "name|contains|all", ["world", "hello"])


def test_regex_modifier_is_case_sensitive_search():
    assert value_matches('{"Action" : "*"}', r'"Action"\s*:\s*"\*"', ["re"])
    assert not value_matches('{"ACTION":"*"}', r'"Action"\s*:\s*"\*"', ["re"])


def test_exists_and_null():
    event = {"a": 1, "b": None}
    assert field_matches(event, "a|exists", True)
    assert field_matches(event, "missing|exists", False)
    assert not field_matches(event, "b|exists", True)
    assert field_matches(event, "missing", None)  # field: null means "has no value"


def test_fieldref_compares_two_fields():
    event = {"x": "alice", "y": "ALICE", "z": "bob"}
    assert field_matches(event, "x|fieldref", "y")
    assert not field_matches(event, "x|fieldref", "z")
    assert not field_matches(event, "x|fieldref", "missing")


def test_unsupported_modifier_stops_with_an_error():
    with pytest.raises(ValueError):
        field_matches({"a": "x"}, "a|base64", "x")


def test_keyword_selection_is_not_supported():
    rule = {"detection": {"keywords": ["foo", "bar"], "condition": "keywords"}}
    with pytest.raises(ValueError):
        rule_matches(rule, {})


SELECTIONS = {"a": {"x": 1}, "b": {"x": 2}, "c": {"x": 3}, "filter_a": {"x": 1}}


@pytest.mark.parametrize("text,event,expected", [
    ("a", {"x": 1}, True),
    ("a and b", {"x": 1}, False),
    ("a or b", {"x": 2}, True),
    ("a and not b", {"x": 1}, True),
    ("not a", {"x": 1}, False),
    ("not (a or b) and c", {"x": 3}, True),
    ("not (a or b) and c", {"x": 1}, False),
    ("1 of them", {"x": 3}, True),
    ("all of them", {"x": 3}, False),
    ("1 of filter*", {"x": 1}, True),
    ("a and 1 of filter*", {"x": 1}, True),
    ("a or b and c", {"x": 1}, True),   # and binds tighter than or, so this is: a or (b and c)
])
def test_condition_parser(text, event, expected):
    assert Condition(text, SELECTIONS).parse()(event) is expected


def test_condition_errors_are_clear():
    with pytest.raises(ValueError):
        Condition("nothing", SELECTIONS).parse()
    with pytest.raises(ValueError):
        Condition("(a", SELECTIONS).parse()
    with pytest.raises(ValueError):
        Condition("a b", SELECTIONS).parse()


def test_a_list_of_maps_means_any_map_matches():
    rule = {"detection": {"selection": [{"x": 1}, {"y": 2}], "condition": "selection"}}
    assert rule_matches(rule, {"y": 2})
    assert not rule_matches(rule, {"x": 9})
