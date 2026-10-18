from shiftguard.graph import arn_for
from shiftguard.techniques.common import policies_of, can_do

NAME = "CreatePolicyVersion"
SEVERITY = "HIGH"
ATTACK = "T1098.003"
REQUIRES = ["iam:CreatePolicyVersion"]
WHAT = "write a new default version of a policy attached to you, so you give yourself admin"
FIX = "remove iam:CreatePolicyVersion, or scope Resource to a policy that is not attached to the same principal"


def find(g, a):
    found = []
    for p in policies_of(g, a):
        data = g.nodes[p]
        if data.get("inline") or data.get("aws_managed"):
            continue  # only customer managed policies have versions I can write
        if can_do(g, a, "iam:CreatePolicyVersion", arn_for("policy", data["name"])):
            found.append(("ADMIN", f"iam:CreatePolicyVersion on policy {data['name']}"))
    return found
