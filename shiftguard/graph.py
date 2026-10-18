import networkx as nx

from shiftguard.parser import get_all_resources, get_config_resources
from shiftguard.policy import parse_policy

ACCOUNT_ID = "123456789012"  # fake id, the plan never knows the real one

# AWS managed policies that show up in my labs. TODO: load these from a file
AWS_MANAGED = {
    "arn:aws:iam::aws:policy/AdministratorAccess": [
        {"effect": "Allow", "actions": ["*"], "resources": ["*"]}
    ],
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess": [
        {"effect": "Allow", "actions": ["s3:Get*", "s3:List*"], "resources": ["*"]}
    ],
}

KINDS = {"aws_iam_user": "user", "aws_iam_role": "role", "aws_iam_group": "group"}


def arn_for(kind, name):
    return f"arn:aws:iam::{ACCOUNT_ID}:{kind}/{name}"


def find_field(res, field, config, by_address):
    # known values are in planned_values. Unknown ones (like an arn) are missing,
    # so fall back to the references in the configuration section
    value = res["values"].get(field)
    if value is not None:
        return value
    expr = config.get(res["address"], {}).get("expressions", {}).get(field, {})
    for ref in expr.get("references", []):
        if ref in by_address:
            return by_address[ref]  # the resource object it points to
    return None


def build_graph(plan):
    resources = get_all_resources(plan)
    config = get_config_resources(plan)
    by_address = {r["address"]: r for r in resources}

    g = nx.DiGraph()
    policy_by_arn = {}

    # pass 1: nodes (principals and managed policies)
    for r in resources:
        t = r["type"]
        name = r["values"].get("name")
        if t in KINDS:
            kind = KINDS[t]
            g.add_node(f"{kind}:{name}", kind=kind, name=name, arn=arn_for(kind, name))
            if kind == "role":
                g.nodes[f"role:{name}"]["trust"] = parse_policy(r["values"]["assume_role_policy"])
        elif t == "aws_iam_policy":
            key = f"policy:{name}"
            g.add_node(key, kind="policy", name=name, statements=parse_policy(r["values"]["policy"]))
            policy_by_arn[arn_for("policy", name)] = key

    for arn, statements in AWS_MANAGED.items():
        key = "policy:" + arn.split("/")[-1]
        g.add_node(key, kind="policy", name=arn.split("/")[-1], statements=statements, aws_managed=True)
        policy_by_arn[arn] = key

    # pass 2: edges
    for r in resources:
        t = r["type"]
        v = r["values"]

        # inline policies: make a policy node and link the owner to it
        if t in ("aws_iam_user_policy", "aws_iam_role_policy", "aws_iam_group_policy"):
            kind = t.split("_")[2]
            owner = find_field(r, kind, config, by_address)
            owner_name = owner["values"]["name"] if isinstance(owner, dict) else owner
            key = f"inline:{owner_name}/{v['name']}"
            g.add_node(key, kind="policy", name=v["name"], inline=True, statements=parse_policy(v["policy"]))
            g.add_edge(f"{kind}:{owner_name}", key, edge="has_policy")

        # attachments: owner -> managed policy
        elif t in ("aws_iam_user_policy_attachment", "aws_iam_role_policy_attachment", "aws_iam_group_policy_attachment"):
            kind = t.split("_")[2]
            owner = find_field(r, kind, config, by_address)
            owner_name = owner["values"]["name"] if isinstance(owner, dict) else owner
            policy = find_field(r, "policy_arn", config, by_address)
            if isinstance(policy, dict):  # unknown arn, resolved through the reference
                policy = arn_for("policy", policy["values"]["name"])
            if policy in policy_by_arn:
                g.add_edge(f"{kind}:{owner_name}", policy_by_arn[policy], edge="has_policy")
            else:
                print("warning: unknown policy arn", policy)  # TODO: real logging

        # group membership
        elif t == "aws_iam_group_membership":
            for user in v.get("users", []):
                g.add_edge(f"user:{user}", f"group:{v['group']}", edge="member_of")
        elif t == "aws_iam_user_group_membership":
            for group in v.get("groups", []):
                g.add_edge(f"user:{v['user']}", f"group:{group}", edge="member_of")

    add_trust_edges(g)
    return g


def add_trust_edges(g):
    # a trust policy says WHO may assume the role. We add an edge principal -> role.
    # Note: the principal also needs sts:AssumeRole in its own policy. paths.py checks that later.
    principals = [n for n, d in g.nodes(data=True) if d["kind"] in ("user", "role")]
    for node, data in list(g.nodes(data=True)):
        if data["kind"] != "role":
            continue
        for s in data["trust"]:
            if s["effect"] != "Allow":
                continue
            for who in s["principals"]:
                if who == "*" or who == f"arn:aws:iam::{ACCOUNT_ID}:root":
                    # anyone / anyone in the account
                    for p in principals:
                        if p != node:
                            g.add_edge(p, node, edge="can_assume", via="account")
                elif who.endswith(".amazonaws.com"):
                    data.setdefault("services", []).append(who)
                else:
                    for p in principals:
                        if g.nodes[p]["arn"] == who:
                            g.add_edge(p, node, edge="can_assume", via="named")
