from shiftguard.techniques.common import roles, can_do

NAME = "PassRole+Lambda"
SEVERITY = "HIGH"
ATTACK = "T1548.005"
REQUIRES = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
WHAT = "create a Lambda function with a more powerful role and invoke it to run code as that role"
FIX = "scope iam:PassRole to specific low-privilege role ARNs and add an iam:PassedToService condition"


def find(g, a):
    found = []
    if not (can_do(g, a, "lambda:CreateFunction") and can_do(g, a, "lambda:InvokeFunction")):
        return found
    for r in roles(g):
        trusts_lambda = "lambda.amazonaws.com" in g.nodes[r].get("services", [])
        if r != a and trusts_lambda and can_do(g, a, "iam:PassRole", g.nodes[r]["arn"]):
            found.append((r, f"iam:PassRole on {r} + lambda:CreateFunction + lambda:InvokeFunction"))
    return found
