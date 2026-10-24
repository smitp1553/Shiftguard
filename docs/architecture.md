# Architecture

How ShiftGuard turns a Terraform plan into escalation paths and detections.

```mermaid
flowchart LR
    plan[plan.json] --> parser
    parser --> graph[graph.py<br>IAM graph]
    graph --> tech[techniques/<br>13 checks]
    tech --> esc[paths.py<br>escalation graph]
    esc --> findings[findings]
    findings --> cov[coverage.py<br>adds Sigma rules]
    cov --> report[report.py<br>text, JSON, Mermaid]
    cov --> nav[navigator.py<br>ATT&CK layer]
    report --> cli[cli.py<br>exit code 0 or 1]
    rules[detections/sigma] --> cov
    rules --> matcher[matcher.py<br>test on CloudTrail JSON]
```

## The pieces

| Module | Job |
|---|---|
| `parser.py` | loads the plan, reads resources from `planned_values` (including child modules) and references from `configuration` |
| `policy.py` | parses policy JSON, matches actions and resources with wildcards, expands actions |
| `graph.py` | builds the IAM graph: users, roles, groups, policies, with `has_policy`, `member_of` and `can_assume` edges |
| `techniques/` | one file per technique. Each has `find(graph, principal)` that returns the targets that principal can reach with that technique |
| `paths.py` | joins technique results into an escalation graph and finds the cheapest path to ADMIN |
| `coverage.py` | maps each technique to its Sigma rule(s), or to a written reason there is none |
| `report.py` | text, JSON and Mermaid output |
| `navigator.py` | builds an ATT&CK Navigator layer (green = rule, red = gap) |
| `cli.py` | command line and exit code |
| `detections/matcher.py` | small Sigma matcher so the rules can be tested without a SIEM |

## Two graphs

The first graph is the **IAM graph**: it records what exists and what is attached to what. The second is the **escalation graph**: an edge A to B means "A can become B in one step". Each technique adds edges. A principal that already has admin gets an edge to the end node ADMIN with cost 0. Everyone else needs at least one step.

`shortest_path` with `weight="cost"` then gives the cheapest chain. The cost on the admin edge is 0, so a one-step path reports as one step and not two.

## Why two passes in graph.py

A plan does not contain values that are only known after apply, such as the ARN of a policy created in the same plan. The first pass adds every node. The second pass resolves links, and when a value is unknown it follows the `references` in the `configuration` section to find the real resource.

## Why techniques are separate files

Each technique has its own name, severity, ATT&CK ID, required permissions, a description and a fix. That makes it easy to add one, test one, and generate documentation from them. The order in `techniques/__init__.py` matters: if two techniques give the same step, the first one is reported and the other is listed as "also possible with".

## Detections are separate from the analyzer

The analyzer and the Sigma rules do not import each other. `coverage.py` is the only link, and a test makes sure that every technique either has a rule or a written reason. This keeps the rules usable on their own in any SIEM that Sigma supports.

## Design choices and trade-offs

- **Plan, not apply.** Safe and free, and it allows a pull request check. The cost is that unknown values must be resolved from references.
- **Hand-written techniques, not a generic engine.** Easy to read and test. It will not find paths nobody has written down.
- **networkx.** Simple and well known. Fine for a small account, not tuned for large ones.
- **Sigma for detections.** One rule format that converts to Splunk and Elasticsearch, instead of writing queries per vendor.
- **Simple functions, few classes.** Written to be readable by one student.