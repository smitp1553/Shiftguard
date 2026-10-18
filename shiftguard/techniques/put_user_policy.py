from shiftguard.techniques.common import can_do

NAME = "PutUserPolicy"
SEVERITY = "HIGH"
ATTACK = "T1098.003"
REQUIRES = ["iam:PutUserPolicy"]
WHAT = "write an inline admin policy on your own user"
FIX = "remove iam:PutUserPolicy, or scope Resource so it cannot target your own user"


def find(g, a):
    if g.nodes[a]["kind"] != "user":
        return []
    if can_do(g, a, "iam:PutUserPolicy", g.nodes[a]["arn"]):
        return [("ADMIN", f"iam:PutUserPolicy on {a}")]
    return []
