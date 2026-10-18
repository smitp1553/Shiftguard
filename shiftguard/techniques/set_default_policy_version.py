from shiftguard.graph import arn_for
from shiftguard.techniques.common import policies_of, can_do

NAME = "SetDefaultPolicyVersion"
SEVERITY = "MEDIUM"
ATTACK = "T1098.003"
REQUIRES = ["iam:SetDefaultPolicyVersion"]
WHAT = "switch a policy attached to you back to an older, more permissive version"
FIX = "remove iam:SetDefaultPolicyVersion, or scope Resource to a policy that is not attached to the same principal"


def find(g, a):
    found = []
    for p in policies_of(g, a):
        data = g.nodes[p]
        if data.get("inline") or data.get("aws_managed"):
            continue
        if can_do(g, a, "iam:SetDefaultPolicyVersion", arn_for("policy", data["name"])):
            # the plan cannot show old versions, so this one needs a manual check
            found.append(("ADMIN", f"iam:SetDefaultPolicyVersion on policy {data['name']} (only works if an older permissive version exists)"))
    return found
