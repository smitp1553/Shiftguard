from shiftguard.techniques.common import roles, can_do, can_assume

NAME = "AttachRolePolicy"
SEVERITY = "HIGH"
ATTACK = "T1098.003"
REQUIRES = ["iam:AttachRolePolicy", "sts:AssumeRole"]
WHAT = "attach AdministratorAccess to a role you can assume, then assume it"
FIX = "remove iam:AttachRolePolicy, or scope Resource to roles you cannot assume"


def find(g, a):
    found = []
    for r in roles(g):
        if r != a and can_do(g, a, "iam:AttachRolePolicy", g.nodes[r]["arn"]) and can_assume(g, a, r):
            found.append(("ADMIN", f"iam:AttachRolePolicy on {r}, then sts:AssumeRole"))
    return found
