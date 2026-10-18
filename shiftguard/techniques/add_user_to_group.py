from shiftguard.techniques.common import groups, can_do, is_admin

NAME = "AddUserToGroup"
SEVERITY = "HIGH"
ATTACK = "T1098.003"
REQUIRES = ["iam:AddUserToGroup"]
WHAT = "add your own user to a group that has admin permissions"
FIX = "remove iam:AddUserToGroup, or scope Resource to groups without admin permissions"


def find(g, a):
    if g.nodes[a]["kind"] != "user":
        return []
    found = []
    for grp in groups(g):
        if is_admin(g, grp) and can_do(g, a, "iam:AddUserToGroup", g.nodes[grp]["arn"]):
            found.append(("ADMIN", f"iam:AddUserToGroup on {grp}"))
    return found
