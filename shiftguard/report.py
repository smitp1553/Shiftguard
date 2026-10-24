def to_mermaid(g):
    # turns the graph into text that Mermaid can draw (paste it on mermaid.live or view it on GitHub)
    lines = ["graph LR"]
    ids = {}
    for i, (node, data) in enumerate(g.nodes(data=True)):
        ids[node] = f"n{i}"
        label = node.replace('"', "")
        if data["kind"] == "policy":
            lines.append(f'  n{i}["{label}"]')
        elif data["kind"] == "role":
            lines.append(f'  n{i}(("{label}"))')
        else:
            lines.append(f'  n{i}("{label}")')

    for a, b, data in g.edges(data=True):
        if data["edge"] == "has_policy":
            lines.append(f"  {ids[a]} -->|has policy| {ids[b]}")
        elif data["edge"] == "member_of":
            lines.append(f"  {ids[a]} -->|member of| {ids[b]}")
        else:
            lines.append(f"  {ids[a]} -.->|trust allows ({data['via']})| {ids[b]}")
    return "\n".join(lines)


def findings_text(findings):
    if not findings:
        return "No escalation paths found."

    lines = []
    for f in findings:
        word = "step" if f["length"] == 1 else "steps"
        lines.append(f"{f['severity']}: {f['principal']} -> ADMIN in {f['length']} {word}")
        for i, s in enumerate(f["steps"], 1):
            lines.append(f"  {i}. {s['detail']}  [{s['technique']}, {s['attack']}]")
            lines.append(f"     becomes: {s['to']}")
            if "rules" in s:
                if s["rules"]:
                    for r in s["rules"]:
                        lines.append(f"     detect with: {r['title']} ({r['id']})")
                else:
                    lines.append("     detect with: no sigma rule yet")
            if s["also"]:
                lines.append(f"     same step also possible with: {', '.join(s['also'])}")
        lines.append(f"  Fix: {f['steps'][0]['fix']}")
        lines.append("")
    return "\n".join(lines).rstrip()


def findings_summary(findings, how_many_principals):
    return f"{len(findings)} of {how_many_principals} principals can reach admin"


def findings_json(findings):
    import json
    return json.dumps(findings, indent=2)


def paths_mermaid(findings):
    # one diagram with every escalation path, starting points on the left, ADMIN on the right
    lines = ["graph LR", '  ADMIN(["ADMIN"])']
    ids = {"ADMIN": "ADMIN"}
    seen = set()

    def node_id(name):
        if name not in ids:
            ids[name] = f"p{len(ids)}"
            lines.append(f'  {ids[name]}("{name}")')
        return ids[name]

    for f in findings:
        for s in f["steps"]:
            a, b = node_id(s["from"]), node_id(s["to"])
            if (a, b) not in seen:
                seen.add((a, b))
                lines.append(f"  {a} -->|{s['technique']}| {b}")
        # the last principal in the path is already admin, so it points at ADMIN
        last = node_id(f["steps"][-1]["to"])
        if last != "ADMIN" and (last, "ADMIN") not in seen:
            seen.add((last, "ADMIN"))
            lines.append(f"  {last} --> ADMIN")
    return "\n".join(lines)
