import json
from fnmatch import fnmatchcase


def parse_policy(doc):
    # the plan stores policies as JSON strings, so turn the string into a dict first
    if isinstance(doc, str):
        doc = json.loads(doc)

    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        # AWS allows a single statement without the list
        statements = [statements]

    result = []
    for s in statements:
        result.append({
            "effect": s.get("Effect", "Allow"),
            "actions": to_list(s.get("Action")),
            "resources": to_list(s.get("Resource")),
            "principals": get_principals(s.get("Principal")),
        })
        # TODO: NotAction, NotResource and Condition are ignored in v1
    return result


def get_principals(p):
    # only trust policies have a Principal. It is "*" or {"AWS": ..., "Service": ...}
    if p is None:
        return []
    if isinstance(p, str):
        return [p]
    found = []
    for value in p.values():
        found.extend(to_list(value))
    return found


def to_list(x):
    # Action and Resource can be a string or a list
    if x is None:
        return []
    if isinstance(x, str):
        return [x]
    return list(x)


def action_matches(pattern, action):
    # IAM action names are not case sensitive, and * matches anything
    return fnmatchcase(action.lower(), pattern.lower())


def resource_matches(pattern, resource):
    return fnmatchcase(resource, pattern)


def allows(statements, action, resource="*"):
    # v1: only looks at Allow statements, explicit Deny is not handled yet
    # TODO: handle Deny (version 2)
    for s in statements:
        if s["effect"] != "Allow":
            continue
        action_ok = any(action_matches(p, action) for p in s["actions"])
        resource_ok = any(resource_matches(p, resource) for p in s["resources"])
        if action_ok and resource_ok:
            return True
    return False


def expand_actions(statements, known_actions):
    # which of the actions we care about does this policy allow? (this is how iam:* gets expanded)
    found = []
    for action in known_actions:
        for s in statements:
            if s["effect"] == "Allow" and any(action_matches(p, action) for p in s["actions"]):
                found.append(action)
                break
    return found
