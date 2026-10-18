import json
from pathlib import Path

import pytest

from shiftguard.graph import build_graph
from shiftguard.parser import load_plan
from shiftguard.paths import find_paths
from shiftguard.report import findings_text, findings_json, paths_mermaid

ROOT = Path(__file__).parent.parent
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
ACCOUNT = "arn:aws:iam::123456789012"


# ---- tiny helpers to build plans by hand ----

def res(rtype, key, **values):
    return {"address": f"{rtype}.{key}", "type": rtype, "values": values}


def user(name):
    return res("aws_iam_user", name, name=name)


def group(name):
    return res("aws_iam_group", name, name=name)


def role(name, principal):
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}]}
    return res("aws_iam_role", name, name=name, assume_role_policy=json.dumps(trust))


def inline(kind, owner, actions, resource="*", name=None):
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}]}
    n = name or f"{owner}-inline"
    return res(f"aws_iam_{kind}_policy", n, name=n, policy=json.dumps(doc), **{kind: owner})


def admin(kind, owner):
    return res(f"aws_iam_{kind}_policy_attachment", f"{owner}-admin", policy_arn=ADMIN_ARN, **{kind: owner})


def managed(name, actions, resource="*"):
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}]}
    return res("aws_iam_policy", name, name=name, policy=json.dumps(doc))


def attach(kind, owner, policy_name):
    return res(f"aws_iam_{kind}_policy_attachment", f"{owner}-{policy_name}", policy_arn=f"{ACCOUNT}:policy/{policy_name}", **{kind: owner})


def member(user_name, group_name):
    return res("aws_iam_user_group_membership", f"{user_name}-{group_name}", user=user_name, groups=[group_name])


def run(*resources):
    plan = {"planned_values": {"root_module": {"resources": list(resources)}}}
    return find_paths(build_graph(plan))


def who(findings):
    return [f["principal"] for f in findings]


EC2 = {"Service": "ec2.amazonaws.com"}
LAMBDA = {"Service": "lambda.amazonaws.com"}
ROOT_TRUST = {"AWS": f"{ACCOUNT}:root"}


# ---- one test per technique, plus a negative case ----

def test_create_policy_version():
    f = run(user("u"), managed("p", ["iam:CreatePolicyVersion"]), attach("user", "u", "p"))
    assert who(f) == ["user:u"] and f[0]["steps"][0]["technique"] == "CreatePolicyVersion"


def test_create_policy_version_on_other_policy_is_not_a_path():
    f = run(user("u"), managed("p", ["iam:CreatePolicyVersion"], f"{ACCOUNT}:policy/other"), attach("user", "u", "p"))
    assert f == []


def test_set_default_policy_version():
    f = run(user("u"), managed("p", ["iam:SetDefaultPolicyVersion"]), attach("user", "u", "p"))
    assert f[0]["steps"][0]["technique"] == "SetDefaultPolicyVersion" and f[0]["severity"] == "MEDIUM"


def test_attach_user_policy():
    f = run(user("u"), inline("user", "u", ["iam:AttachUserPolicy"]))
    assert f[0]["steps"][0]["technique"] == "AttachUserPolicy"


def test_attach_user_policy_on_someone_else_only():
    f = run(user("u"), user("v"), inline("user", "u", ["iam:AttachUserPolicy"], f"{ACCOUNT}:user/v"))
    assert f == []


def test_put_user_policy():
    f = run(user("u"), inline("user", "u", ["iam:PutUserPolicy"]))
    assert f[0]["steps"][0]["technique"] == "PutUserPolicy"


def test_attach_role_policy_needs_a_role_i_can_assume():
    yes = run(user("u"), role("r", {"AWS": f"{ACCOUNT}:user/u"}), inline("user", "u", ["iam:AttachRolePolicy"]))
    no = run(user("u"), role("r", EC2), inline("user", "u", ["iam:AttachRolePolicy"]))
    assert who(yes) == ["user:u"] and yes[0]["steps"][0]["technique"] == "AttachRolePolicy"
    assert no == []


def test_put_role_policy_needs_a_role_i_can_assume():
    yes = run(user("u"), role("r", {"AWS": f"{ACCOUNT}:user/u"}), inline("user", "u", ["iam:PutRolePolicy"]))
    no = run(user("u"), role("r", EC2), inline("user", "u", ["iam:PutRolePolicy"]))
    assert yes[0]["steps"][0]["technique"] == "PutRolePolicy"
    assert no == []


def test_add_user_to_group_only_if_group_is_admin():
    yes = run(user("u"), group("g"), admin("group", "g"), inline("user", "u", ["iam:AddUserToGroup"]))
    no = run(user("u"), group("g"), inline("user", "u", ["iam:AddUserToGroup"]))
    assert yes[0]["steps"][0]["technique"] == "AddUserToGroup"
    assert no == []


def test_create_access_key_for_admin_user():
    f = run(user("u"), user("boss"), admin("user", "boss"), inline("user", "u", ["iam:CreateAccessKey"]))
    assert who(f) == ["user:u"] and f[0]["steps"][0]["to"] == "user:boss"


def test_create_access_key_for_own_user_only_is_safe():
    f = run(user("u"), user("boss"), admin("user", "boss"), inline("user", "u", ["iam:CreateAccessKey"], f"{ACCOUNT}:user/u"))
    assert f == []


def test_login_profile():
    f = run(user("u"), user("boss"), admin("user", "boss"), inline("user", "u", ["iam:UpdateLoginProfile"]))
    assert f[0]["steps"][0]["technique"] == "CreateLoginProfile"


def test_update_assume_role_policy():
    f = run(user("u"), role("r", EC2), admin("role", "r"), inline("user", "u", ["iam:UpdateAssumeRolePolicy"]))
    assert f[0]["steps"][0]["technique"] == "UpdateAssumeRolePolicy"


def test_assume_role_with_account_trust_needs_my_own_permission():
    yes = run(user("u"), role("r", ROOT_TRUST), admin("role", "r"), inline("user", "u", ["sts:AssumeRole"]))
    no = run(user("u"), role("r", ROOT_TRUST), admin("role", "r"))
    assert who(yes) == ["user:u"]
    assert no == []


def test_assume_role_named_in_trust_policy_needs_no_permission():
    f = run(user("u"), role("r", {"AWS": f"{ACCOUNT}:user/u"}), admin("role", "r"))
    assert who(f) == ["user:u"]


def test_passrole_ec2():
    f = run(user("u"), role("r", EC2), admin("role", "r"), inline("user", "u", ["iam:PassRole", "ec2:RunInstances"]))
    assert f[0]["steps"][0]["technique"] == "PassRole+RunInstances"


def test_passrole_ec2_needs_runinstances_and_an_ec2_role():
    no_run = run(user("u"), role("r", EC2), admin("role", "r"), inline("user", "u", ["iam:PassRole"]))
    wrong_service = run(user("u"), role("r", LAMBDA), admin("role", "r"), inline("user", "u", ["iam:PassRole", "ec2:RunInstances"]))
    assert no_run == [] and wrong_service == []


def test_passrole_lambda():
    f = run(user("u"), role("r", LAMBDA), admin("role", "r"),
            inline("user", "u", ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]))
    assert f[0]["steps"][0]["technique"] == "PassRole+Lambda"


def test_passrole_lambda_needs_invoke_too():
    f = run(user("u"), role("r", LAMBDA), admin("role", "r"), inline("user", "u", ["iam:PassRole", "lambda:CreateFunction"]))
    assert f == []


# ---- chains, wildcards, groups ----

def test_two_step_chain():
    f = run(user("a"), user("b"),
            inline("user", "a", ["iam:CreateAccessKey"], f"{ACCOUNT}:user/b"),
            inline("user", "b", ["iam:AttachUserPolicy"]))
    by_user = {x["principal"]: x for x in f}
    assert by_user["user:a"]["length"] == 2
    assert by_user["user:b"]["length"] == 1


def test_wildcard_iam_star_is_expanded():
    f = run(user("u"), inline("user", "u", ["iam:*"]))
    assert who(f) == ["user:u"]


def test_permission_from_group_counts():
    f = run(user("u"), group("g"), member("u", "g"), inline("group", "g", ["iam:PutUserPolicy"]))
    assert who(f) == ["user:u"]


def test_admin_principal_is_not_reported():
    assert run(user("boss"), admin("user", "boss")) == []


def test_harmless_user_is_not_reported():
    assert run(user("u"), inline("user", "u", ["s3:GetObject"], "arn:aws:s3:::bucket/*")) == []


def test_deny_is_not_handled_yet():
    # documents a known limit of v1: an explicit Deny does not stop the path
    deny = res("aws_iam_user_policy", "deny", name="deny", user="u", policy=json.dumps(
        {"Statement": [{"Effect": "Deny", "Action": "iam:AttachUserPolicy", "Resource": "*"}]}))
    f = run(user("u"), inline("user", "u", ["iam:AttachUserPolicy"]), deny)
    assert who(f) == ["user:u"]


# ---- output ----

def test_outputs_are_readable():
    f = run(user("u"), inline("user", "u", ["iam:AttachUserPolicy"]))
    assert "HIGH: user:u -> ADMIN in 1 step" in findings_text(f)
    assert json.loads(findings_json(f))[0]["principal"] == "user:u"
    assert paths_mermaid(f).startswith("graph LR")
    assert findings_text([]) == "No escalation paths found."


# ---- the real lab plans (skipped if the plan.json files are missing) ----

def lab(name):
    path = ROOT / "terraform" / name / "plan.json"
    if not path.exists():
        pytest.skip("plan.json not found")
    return find_paths(build_graph(load_plan(path)))


def test_vulnerable_lab_finds_every_planted_path():
    f = lab("lab-vulnerable")
    assert sorted(who(f)) == ["user:dev-alice", "user:dev-bob", "user:dev-carol", "user:dev-dave", "user:dev-erin"]
    by_user = {x["principal"]: x["steps"][0]["technique"] for x in f}
    assert by_user["user:dev-alice"] == "CreatePolicyVersion"
    assert by_user["user:dev-bob"] == "AttachUserPolicy"
    assert by_user["user:dev-carol"] == "PassRole+RunInstances"
    assert by_user["user:dev-dave"] == "CreateAccessKey"
    assert by_user["user:dev-erin"] == "AssumeRole"


def test_vulnerable_lab_does_not_flag_frank():
    assert "user:dev-frank" not in who(lab("lab-vulnerable"))


def test_safe_lab_has_no_paths():
    assert lab("lab-safe") == []
