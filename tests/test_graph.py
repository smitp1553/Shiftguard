import json
from pathlib import Path

import pytest

from shiftguard.graph import build_graph
from shiftguard.parser import load_plan
from shiftguard.report import to_mermaid

ROOT = Path(__file__).parent.parent


def trust(principal):
    return json.dumps({"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]})


def small_plan():
    # shaped like real terraform output: the policy arn is NOT in planned_values,
    # only a reference in the configuration section
    return {
        "planned_values": {"root_module": {"resources": [
            {"address": "aws_iam_user.alice", "type": "aws_iam_user", "values": {"name": "alice"}},
            {"address": "aws_iam_policy.p", "type": "aws_iam_policy", "values": {
                "name": "p", "policy": '{"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}'}},
            {"address": "aws_iam_user_policy_attachment.a", "type": "aws_iam_user_policy_attachment", "values": {"user": "alice"}},
        ], "child_modules": [{"resources": [
            {"address": "module.m.aws_iam_role.r", "type": "aws_iam_role", "values": {
                "name": "r", "assume_role_policy": trust({"AWS": "arn:aws:iam::123456789012:user/alice"})}},
        ]}]}},
        "configuration": {"root_module": {"resources": [
            {"address": "aws_iam_user_policy_attachment.a", "expressions": {
                "policy_arn": {"references": ["aws_iam_policy.p.arn", "aws_iam_policy.p"]}}},
        ]}},
    }


def test_unknown_arn_is_resolved_from_configuration():
    g = build_graph(small_plan())
    assert g.has_edge("user:alice", "policy:p")


def test_resources_in_child_modules_become_nodes():
    g = build_graph(small_plan())
    assert g.nodes["role:r"]["kind"] == "role"


def test_named_trust_gives_edge_only_for_that_user():
    g = build_graph(small_plan())
    assert g.edges["user:alice", "role:r"]["via"] == "named"


def test_mermaid_has_every_node():
    g = build_graph(small_plan())
    text = to_mermaid(g)
    assert text.startswith("graph LR")
    assert "user:alice" in text and "role:r" in text


# the tests below use the real lab plans, so they are skipped if the file is missing
def lab_graph(name):
    path = ROOT / "terraform" / name / "plan.json"
    if not path.exists():
        pytest.skip("plan.json not found")
    return build_graph(load_plan(path))


def test_vulnerable_lab_open_trust_reaches_everyone():
    g = lab_graph("lab-vulnerable")
    assert g.has_edge("user:dev-erin", "role:open-admin-role")
    assert g.has_edge("user:dev-frank", "role:open-admin-role")  # trust alone is not enough, paths.py checks AssumeRole


def test_vulnerable_lab_alice_policy_resolved():
    g = lab_graph("lab-vulnerable")
    assert g.has_edge("user:dev-alice", "policy:dev-alice-policy")
    assert g.has_edge("user:admin-user", "policy:AdministratorAccess")


def test_safe_lab_trust_names_only_admin_user():
    g = lab_graph("lab-safe")
    incoming = [a for a, b in g.in_edges("role:admin-role")]
    assert incoming == ["user:admin-user"]
