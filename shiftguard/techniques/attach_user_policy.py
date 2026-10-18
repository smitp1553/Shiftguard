from shiftguard.techniques.common import can_do

NAME = "AttachUserPolicy"
SEVERITY = "HIGH"
ATTACK = "T1098.003"
REQUIRES = ["iam:AttachUserPolicy"]
WHAT = "attach AdministratorAccess to your own user"
FIX = "remove iam:AttachUserPolicy, or scope Resource so it cannot target your own user"


def find(g, a):
    if g.nodes[a]["kind"] != "user":
        return []
    if can_do(g, a, "iam:AttachUserPolicy", g.nodes[a]["arn"]):
        return [("ADMIN", f"iam:AttachUserPolicy on {a}")]
    return []
