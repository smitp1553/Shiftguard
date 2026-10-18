from shiftguard.techniques.common import roles, can_assume

NAME = "AssumeRole"
SEVERITY = "HIGH"
ATTACK = "T1548.005"
REQUIRES = ["sts:AssumeRole"]
WHAT = "assume a role whose trust policy lets you in"
FIX = "narrow the role's trust policy to the exact principals that need it, and scope sts:AssumeRole to specific role ARNs"


def find(g, a):
    found = []
    for r in roles(g):
        if r != a and can_assume(g, a, r):
            found.append((r, f"sts:AssumeRole into {r}"))
    return found
