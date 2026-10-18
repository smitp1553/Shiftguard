from shiftguard.techniques.common import roles, can_do

NAME = "PassRole+RunInstances"
SEVERITY = "HIGH"
ATTACK = "T1548.005"
REQUIRES = ["iam:PassRole", "ec2:RunInstances"]
WHAT = "launch an EC2 instance that runs as a more powerful role, then read its credentials"
FIX = "scope iam:PassRole to specific low-privilege role ARNs and add an iam:PassedToService condition"


def find(g, a):
    found = []
    if not can_do(g, a, "ec2:RunInstances"):
        return found
    for r in roles(g):
        trusts_ec2 = "ec2.amazonaws.com" in g.nodes[r].get("services", [])
        if r != a and trusts_ec2 and can_do(g, a, "iam:PassRole", g.nodes[r]["arn"]):
            found.append((r, f"iam:PassRole on {r} + ec2:RunInstances"))
    # TODO: ec2:RunInstances is only checked against Resource *, scoped ARNs are missed
    return found
