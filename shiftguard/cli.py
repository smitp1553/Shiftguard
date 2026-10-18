import argparse
import sys

from shiftguard.graph import build_graph
from shiftguard.parser import load_plan
from shiftguard.paths import find_paths
from shiftguard.report import findings_text, findings_summary, findings_json, paths_mermaid, to_mermaid
from shiftguard.techniques.common import principals


def main():
    ap = argparse.ArgumentParser(description="find IAM privilege escalation paths in a terraform plan.json")
    ap.add_argument("plan", help="path to plan.json")
    ap.add_argument("--json", help="write the findings to this json file")
    ap.add_argument("--graph", help="write the full IAM graph as a mermaid markdown file")
    ap.add_argument("--paths", help="write the escalation paths as a mermaid markdown file")
    args = ap.parse_args()

    plan = load_plan(args.plan)
    g = build_graph(plan)
    findings = find_paths(g)

    print(findings_text(findings))
    print()
    print(findings_summary(findings, len(principals(g))))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(findings_json(findings))
    if args.graph:
        with open(args.graph, "w", encoding="utf-8") as f:
            f.write("```mermaid\n" + to_mermaid(g) + "\n```\n")
    if args.paths:
        with open(args.paths, "w", encoding="utf-8") as f:
            f.write("```mermaid\n" + paths_mermaid(findings) + "\n```\n")

    # exit code 1 makes a CI job fail when a path to admin is found
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
