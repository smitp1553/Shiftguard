from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent.parent / "detections" / "sigma"

# ATT&CK v19 (April 2026) revoked these. `sigma check` found them in my trail rule.
# old tag -> what to use now
REVOKED_TAGS = {
    "attack.t1562.008": "attack.t1685.002",
    "attack.defense-evasion": "attack.stealth or attack.defense-impairment",
}


def test_no_rule_uses_a_revoked_attack_tag():
    for path in sorted(RULES_DIR.glob("*.yml")):
        tags = yaml.safe_load(path.read_text(encoding="utf-8"))["tags"]
        for tag in tags:
            assert tag not in REVOKED_TAGS, f"{path.name} uses {tag}, use {REVOKED_TAGS[tag]}"
