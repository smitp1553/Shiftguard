from shiftguard.techniques import ALL


def main():
    print("# Escalation techniques covered by ShiftGuard\n")
    print("| Technique | Needs | What it lets an attacker do | Severity | ATT&CK |")
    print("|---|---|---|---|---|")
    for t in ALL:
        print(f"| {t.NAME} | {', '.join(t.REQUIRES)} | {t.WHAT} | {t.SEVERITY} | {t.ATTACK} |")


if __name__ == "__main__":
    main()
