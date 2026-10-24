# builds an ATT&CK Navigator layer that shows which techniques have a sigma rule
import json

from shiftguard.coverage import COVERAGE, all_rules
from shiftguard.techniques import ALL

GREEN = "#8ec843"   # at least one rule
RED = "#ff6666"     # shiftguard finds it but no rule yet


def attack_ids_from_tags(tags):
    # "attack.t1098.003" -> "T1098.003", tactic tags are skipped
    ids = []
    for t in tags:
        parts = t.split(".")
        if len(parts) >= 2 and parts[0] == "attack" and parts[1].startswith("t") and parts[1][1:].isdigit():
            ids.append(".".join(parts[1:]).upper())
    return ids


def build_layer():
    rules = all_rules()
    ids = {}  # technique id -> info

    def entry(tid):
        return ids.setdefault(tid, {"rules": [], "no_rule": []})

    for r in rules:
        for tid in attack_ids_from_tags(r["tags"]):
            entry(tid)["rules"].append(r["title"])

    for t in ALL:
        if not COVERAGE[t.NAME][0]:
            entry(t.ATTACK)["no_rule"].append(t.NAME)

    techniques = []
    for tid in sorted(ids):
        info = ids[tid]
        comment = []
        if info["rules"]:
            comment.append("Sigma rules: " + "; ".join(sorted(set(info["rules"]))))
        if info["no_rule"]:
            comment.append("Found by ShiftGuard but no rule yet: " + ", ".join(info["no_rule"]))
        techniques.append({
            "techniqueID": tid,
            "score": len(set(info["rules"])),
            "color": GREEN if info["rules"] else RED,
            "comment": " | ".join(comment),
        })

    return {
        "name": "ShiftGuard detection coverage",
        "versions": {"attack": "20", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Green = at least one Sigma rule in detections/sigma. Red = ShiftGuard finds the technique but there is no rule yet. Scores = number of rules.",
        "filters": {"platforms": ["AWS"]},
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": [
            {"label": "has a sigma rule", "color": GREEN},
            {"label": "no rule yet", "color": RED},
        ],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def layer_json():
    return json.dumps(build_layer(), indent=2)