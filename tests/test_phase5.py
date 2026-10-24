import json
import subprocess
import sys
from pathlib import Path

from shiftguard.coverage import COVERAGE, RULES_DIR, add_detections, all_rules, rules_for
from shiftguard.graph import build_graph
from shiftguard.navigator import attack_ids_from_tags, build_layer
from shiftguard.parser import load_plan
from shiftguard.paths import find_paths
from shiftguard.report import findings_text
from shiftguard.techniques import ALL

ROOT = Path(__file__).resolve().parent.parent
VULN = ROOT / "terraform" / "lab-vulnerable" / "plan.json"
SAFE = ROOT / "terraform" / "lab-safe" / "plan.json"


def test_every_technique_is_listed_in_coverage():
    # a new technique must get a rule or an honest "no rule" reason
    for t in ALL:
        assert t.NAME in COVERAGE, f"{t.NAME} is missing from COVERAGE"
    for name in COVERAGE:
        assert name in [t.NAME for t in ALL], f"{name} in COVERAGE is not a technique"


def test_a_gap_has_a_reason():
    for name, (rules, why) in COVERAGE.items():
        if not rules:
            assert why, f"{name} has no rule and no reason"


def test_every_mapped_rule_file_exists_and_has_an_id():
    for name in COVERAGE:
        for r in rules_for(name):
            assert (RULES_DIR / r["file"]).exists()
            assert len(r["id"]) == 36


def test_nine_of_thirteen_techniques_have_a_rule():
    covered = [n for n, (rules, _) in COVERAGE.items() if rules]
    assert len(covered) == 9 and len(COVERAGE) == 13


def test_findings_get_rule_ids_and_report_shows_them():
    findings = add_detections(find_paths(build_graph(load_plan(str(VULN)))))
    steps = [s for f in findings for s in f["steps"]]
    assert all("rules" in s for s in steps)
    text = findings_text(findings)
    assert "f33bf442-33f8-4e80-8dec-72d2bcb12abd" in text   # create policy version rule
    assert "no sigma rule yet" in text                     # passrole step


def test_attack_ids_from_tags_skips_tactics():
    assert attack_ids_from_tags(["attack.persistence", "attack.t1098.001", "attack.t1685.002"]) == ["T1098.001", "T1685.002"]


def test_layer_has_the_required_fields():
    layer = build_layer()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["navigator"] >= "4.9.0"
    assert layer["name"]
    for t in layer["techniques"]:
        assert t["techniqueID"].startswith("T")
        assert t["color"].startswith("#")


def test_layer_colors_green_for_rule_and_red_for_gap():
    by_id = {t["techniqueID"]: t for t in build_layer()["techniques"]}
    assert by_id["T1098.001"]["color"] == "#8ec843"
    assert by_id["T1685.002"]["color"] == "#8ec843"   # trail rule, not a shiftguard technique
    assert by_id["T1548.005"]["color"] == "#ff6666"   # assume role and passrole, no rule
    assert "AddUserToGroup" in by_id["T1098.003"]["comment"]


def test_layer_uses_no_revoked_ids():
    ids = {t["techniqueID"] for t in build_layer()["techniques"]}
    assert "T1562.008" not in ids


def test_layer_is_valid_json_and_matches_every_rule_tag():
    layer = json.loads(json.dumps(build_layer()))
    ids = {t["techniqueID"] for t in layer["techniques"]}
    for r in all_rules():
        for tid in attack_ids_from_tags(r["tags"]):
            assert tid in ids


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "shiftguard.cli", *args], cwd=ROOT, capture_output=True, text=True)


def test_cli_exit_codes_like_the_ci_job_expects():
    assert run_cli(str(SAFE)).returncode == 0
    assert run_cli(str(VULN)).returncode == 1


def test_cli_writes_navigator_layer(tmp_path):
    out = tmp_path / "layer.json"
    run_cli(str(SAFE), "--navigator", str(out))
    assert json.loads(out.read_text(encoding="utf-8"))["name"] == "ShiftGuard detection coverage"