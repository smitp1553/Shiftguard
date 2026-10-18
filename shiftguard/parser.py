import json


def load_plan(path):
    with open(path) as f:
        plan = json.load(f)

    # a plan that failed to build is useless to us
    if plan.get("errored"):
        raise ValueError("plan.json says errored=true, fix the terraform first")

    return plan


def get_resources(module):
    found = []

    # this module's own resources
    found.extend(module.get("resources", []))

    # then the same thing for every child module
    for child in module.get("child_modules", []):
        found.extend(get_resources(child))

    return found


def get_all_resources(plan):
    root = plan["planned_values"]["root_module"]
    return get_resources(root)


def get_config_resources(plan):
    # the configuration section is where references live (like which policy an attachment points to)
    # returns {address: resource}
    # TODO: modules are not followed here, so references inside child modules are not resolved
    root = plan.get("configuration", {}).get("root_module", {})
    return {r["address"]: r for r in root.get("resources", [])}
