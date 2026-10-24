# links each escalation technique to the sigma rule(s) that would catch it in cloudtrail
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "detections" / "sigma"

# technique NAME -> rule file names (no .yml). empty list = no rule yet
# the second value says why, so a gap is on purpose and not forgotten
COVERAGE = {
    "CreatePolicyVersion": (["aws_iam_create_policy_version"], ""),
    "SetDefaultPolicyVersion": (["aws_iam_set_default_policy_version"], ""),
    "AttachUserPolicy": (["aws_iam_attach_admin_policy"], ""),
    "AttachRolePolicy": (["aws_iam_attach_admin_policy"], ""),
    "PutUserPolicy": (["aws_iam_put_admin_policy"], ""),
    "PutRolePolicy": (["aws_iam_put_admin_policy"], ""),
    "CreateAccessKey": (["aws_iam_create_access_key_other_user"], ""),
    "CreateLoginProfile": (["aws_iam_login_profile_other_user"], ""),
    "UpdateAssumeRolePolicy": (["aws_iam_update_assume_role_policy"], ""),
    "AddUserToGroup": ([], "TODO: no rule yet"),
    "AssumeRole": ([], "AssumeRole is everywhere in normal traffic, too noisy without context"),
    "PassRole+RunInstances": ([], "PassRole is not its own cloudtrail event (not verified), needs the follow-up call"),
    "PassRole+Lambda": ([], "PassRole is not its own cloudtrail event (not verified), needs the follow-up call"),
}


def load_rule_info(name):
    path = RULES_DIR / f"{name}.yml"
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {"file": f"{name}.yml", "id": rule["id"], "title": rule["title"], "tags": rule["tags"]}


def rules_for(technique_name):
    names, _why = COVERAGE.get(technique_name, ([], "not listed in COVERAGE"))
    return [load_rule_info(n) for n in names]


def add_detections(findings):
    # adds a "rules" list to every step (changes the findings in place)
    for f in findings:
        for s in f["steps"]:
            s["rules"] = [{"id": r["id"], "title": r["title"]} for r in rules_for(s["technique"])]
    return findings


def all_rules():
    return [load_rule_info(p.stem) for p in sorted(RULES_DIR.glob("*.yml"))]