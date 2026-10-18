from shiftguard.policy import allows


def principals(g):
    return [n for n, d in g.nodes(data=True) if d["kind"] in ("user", "role")]


def policies_of(g, node):
    # every policy node that applies to a principal: its own policies plus its groups' policies
    found = []
    for _, target, data in g.out_edges(node, data=True):
        if data["edge"] == "has_policy":
            found.append(target)
        elif data["edge"] == "member_of":
            found.extend(policies_of(g, target))
    return found


def statements_of(g, node):
    result = []
    for p in policies_of(g, node):
        result.extend(g.nodes[p]["statements"])
    return result


def can_do(g, node, action, resource="*"):
    return allows(statements_of(g, node), action, resource)


def is_admin(g, node):
    # admin = an Allow statement with Action * on Resource *
    # TODO: also treat iam:* on * as admin, it is the same in practice
    for s in statements_of(g, node):
        if s["effect"] == "Allow" and "*" in s["actions"] and "*" in s["resources"]:
            return True
    return False


def can_assume(g, a, role):
    # the trust policy must let a in. If it names a directly, that is enough (same account).
    # If it only names the account root, a also needs sts:AssumeRole in its own policy.
    # TODO: cross-account trust is not handled
    if not g.has_edge(a, role):
        return False
    edge = g.edges[a, role]
    if edge.get("edge") != "can_assume":
        return False
    if edge["via"] == "named":
        return True
    return can_do(g, a, "sts:AssumeRole", g.nodes[role]["arn"])


def roles(g):
    return [n for n, d in g.nodes(data=True) if d["kind"] == "role"]


def users(g):
    return [n for n, d in g.nodes(data=True) if d["kind"] == "user"]


def groups(g):
    return [n for n, d in g.nodes(data=True) if d["kind"] == "group"]
