from shiftguard.techniques.common import users, can_do

NAME = "CreateLoginProfile"
SEVERITY = "HIGH"
ATTACK = "T1098.001"
REQUIRES = ["iam:CreateLoginProfile or iam:UpdateLoginProfile"]
WHAT = "set a console password for another user and log in as them"
FIX = "remove iam:CreateLoginProfile and iam:UpdateLoginProfile, or scope them to your own user ARN"


def find(g, a):
    found = []
    for u in users(g):
        if u == a:
            continue
        for action in ("iam:CreateLoginProfile", "iam:UpdateLoginProfile"):
            if can_do(g, a, action, g.nodes[u]["arn"]):
                found.append((u, f"{action} on {u}"))
                break
    return found
