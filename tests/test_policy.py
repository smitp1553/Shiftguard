from shiftguard.policy import parse_policy, allows, expand_actions, action_matches


def test_string_action_and_single_statement():
    doc = '{"Statement": {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}}'
    s = parse_policy(doc)
    assert s[0]["actions"] == ["s3:GetObject"]
    assert s[0]["resources"] == ["*"]


def test_wildcards():
    assert action_matches("iam:*", "iam:CreateAccessKey")
    assert action_matches("*", "sts:AssumeRole")
    assert action_matches("s3:Get*", "s3:GetObject")
    assert not action_matches("iam:*", "s3:GetObject")
    assert action_matches("IAM:createaccesskey", "iam:CreateAccessKey")  # not case sensitive


def test_allows_checks_resource():
    s = parse_policy('{"Statement": [{"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "arn:aws:iam::123456789012:user/dev-dave"}]}')
    assert allows(s, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/dev-dave")
    assert not allows(s, "iam:CreateAccessKey", "arn:aws:iam::123456789012:user/admin-user")


def test_expand_actions():
    s = parse_policy('{"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}')
    found = expand_actions(s, ["iam:CreatePolicyVersion", "s3:GetObject", "iam:PassRole"])
    assert found == ["iam:CreatePolicyVersion", "iam:PassRole"]


def test_deny_is_ignored_in_v1():
    # documents a known limit: explicit Deny is not handled yet
    s = parse_policy('{"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}')
    assert not allows(s, "iam:CreateAccessKey")
