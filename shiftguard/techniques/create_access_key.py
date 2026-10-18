from shiftguard.techniques.common import users, can_do

NAME = "CreateAccessKey"
SEVERITY = "HIGH"
ATTACK = "T1098.001"
REQUIRES = ["iam:CreateAccessKey"]
WHAT = "create an access key for another user and act as them"
FIX = "scope iam:CreateAccessKey to your own user ARN (use a condition on aws:username later)"


def find(g, a):
    found = []
    for u in users(g):
        if u != a and can_do(g, a, "iam:CreateAccessKey", g.nodes[u]["arn"]):
            found.append((u, f"iam:CreateAccessKey on {u}"))
    return found
