from shiftguard.techniques.common import roles, can_do

NAME = "UpdateAssumeRolePolicy"
SEVERITY = "HIGH"
ATTACK = "T1098.003"
REQUIRES = ["iam:UpdateAssumeRolePolicy"]
WHAT = "rewrite a role's trust policy to name yourself, then assume it"
FIX = "remove iam:UpdateAssumeRolePolicy, or scope Resource to roles that are not more powerful than you"


def find(g, a):
    found = []
    for r in roles(g):
        # once the trust policy names me directly, no sts:AssumeRole in my own policy is needed
        if r != a and can_do(g, a, "iam:UpdateAssumeRolePolicy", g.nodes[r]["arn"]):
            found.append((r, f"iam:UpdateAssumeRolePolicy on {r}, then sts:AssumeRole"))
    return found
