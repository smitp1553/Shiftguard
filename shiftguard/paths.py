import networkx as nx

from shiftguard.techniques import ALL
from shiftguard.techniques.common import principals, is_admin

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def escalation_graph(g):
    # new graph: an edge a -> b means "a can become b in one step"
    # "ADMIN" is a made-up end node for "a gets admin permissions on itself"
    esc = nx.DiGraph()
    for a in principals(g):
        if is_admin(g, a):
            esc.add_edge(a, "ADMIN", technique=None, cost=0)  # already admin, the end of every path (costs nothing)
            continue
        for technique in ALL:
            for target, detail in technique.find(g, a):
                if target == a:
                    continue
                if esc.has_edge(a, target):
                    # same step, another technique: remember it but keep the first one
                    esc.edges[a, target]["also"].append(technique.NAME)
                else:
                    esc.add_edge(a, target, technique=technique, detail=detail, also=[], cost=1)
    return esc


def find_paths(g):
    esc = escalation_graph(g)
    findings = []

    for a in principals(g):
        if is_admin(g, a):
            continue  # nothing to escalate to
        try:
            path = nx.shortest_path(esc, a, "ADMIN", weight="cost")
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            continue  # TODO: only one shortest path is kept, there may be others

        steps = []
        for x, y in zip(path, path[1:]):
            edge = esc.edges[x, y]
            if edge["technique"] is None:
                continue  # the "already admin" edge at the end is not a step
            t = edge["technique"]
            steps.append({
                "from": x,
                "to": y,
                "technique": t.NAME,
                "detail": edge["detail"],
                "also": edge["also"],
                "severity": t.SEVERITY,
                "attack": t.ATTACK,
                "what": t.WHAT,
                "fix": t.FIX,
            })

        severity = max((s["severity"] for s in steps), key=lambda s: SEVERITY_ORDER[s])
        findings.append({
            "principal": a,
            "severity": severity,
            "length": len(steps),
            "steps": steps,
        })

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], f["length"], f["principal"]))
    return findings
