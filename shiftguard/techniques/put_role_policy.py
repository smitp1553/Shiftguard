from shiftguard.techniques.common import roles, can_do, can_assume

NAME = "PutRolePolicy"
SEVERITY = "HIGH"
ATTACK = "T1098.003"
REQUIRES = ["iam:PutRolePolicy", "sts:AssumeRole"]
WHAT = "write an inline admin policy on a role you can assume, then assume it"
FIX = "remove iam:PutRolePolicy, or scope Resource to roles you cannot assume"


def find(g, a):
    found = []
    for r in roles(g):
        if r != a and can_do(g, a, "iam:PutRolePolicy", g.nodes[r]["arn"]) and can_assume(g, a, r):
            found.append(("ADMIN", f"iam:PutRolePolicy on {r}, then sts:AssumeRole"))
    return found
