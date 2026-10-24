# makes a safe copy of real cloudtrail events for the repo
# usage: python tools/sanitize_live_events.py live/live-events.json tests/fixtures/cloudtrail_real/real-events.json
# removes: account ids, access key ids, principal ids, ip addresses, user agents, error messages
import json
import re
import sys
from collections import Counter

# (event name, who did it) -> how many of those events to keep (oldest first)
KEEP = {
    ("CreatePolicyVersion", "dev-alice"): 1,
    ("SetDefaultPolicyVersion", "dev-alice"): 1,
    ("AttachUserPolicy", "dev-bob"): 2,
    ("PutUserPolicy", "dev-pete"): 2,
    ("CreateAccessKey", "dev-dave"): 2,
    ("CreateLoginProfile", "dev-lara"): 1,
    ("UpdateAssumeRolePolicy", "dev-quinn"): 1,
    ("CreateAccessKey", "key-manager-role"): 1,   # the assumed role step of the chain
    ("AttachUserPolicy", "smit-admin"): 1,
    ("CreateAccessKey", "smit-admin"): 1,
}

ACCOUNT = re.compile(r"\b\d{12}\b")
KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
PRINCIPAL = re.compile(r"\b(?:AIDA|AROA|AIPA|ANPA)[A-Z0-9]{12,}\b")
IP = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

seen_keys = {}
seen_principals = {}


def fake(table, real, prefix):
    if real not in table:
        table[real] = f"{prefix}{len(table) + 1:04d}"
    return table[real]


def clean_text(s):
    s = KEY_ID.sub(lambda m: fake(seen_keys, m.group(0), "EXAMPLEKEYID"), s)
    s = PRINCIPAL.sub(lambda m: fake(seen_principals, m.group(0), "EXAMPLEPRINCIPAL"), s)
    s = IP.sub("203.0.113.25", s)
    s = ACCOUNT.sub("123456789012", s)
    return s


def clean(x, key=""):
    if isinstance(x, dict):
        return {k: clean(v, k) for k, v in x.items()}
    if isinstance(x, list):
        return [clean(v, key) for v in x]
    if isinstance(x, str):
        if key == "userAgent":
            return "aws-cli/2.0.0 (sanitized)"
        if key == "errorMessage":
            return "REDACTED"
        return clean_text(x)
    return x


def who(e):
    ui = e.get("userIdentity", {})
    if ui.get("type") == "AssumedRole":
        return ui.get("sessionContext", {}).get("sessionIssuer", {}).get("userName")
    return ui.get("userName")


def main():
    if len(sys.argv) != 3:
        print("usage: python tools/sanitize_live_events.py in.json out.json")
        return 2

    data = json.load(open(sys.argv[1], encoding="utf-8"))
    events = sorted(data["Records"], key=lambda e: e["eventTime"])

    left = dict(KEEP)
    kept = []
    for e in events:
        k = (e.get("eventName"), who(e))
        if left.get(k, 0) > 0:
            left[k] -= 1
            kept.append(e)

    out = clean({"Records": kept})
    text = json.dumps(out, indent=2)

    # last check: nothing sensitive may be left
    problems = []
    if re.search(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b", text):
        problems.append("an aws id is still there")
    if any(n != "123456789012" for n in re.findall(r"\b\d{12}\b", text)):
        problems.append("another 12 digit number is still there")
    if any(ip != "203.0.113.25" for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)):
        problems.append("an ip address is still there")
    if problems:
        print("NOT WRITTEN:", "; ".join(problems))
        return 1

    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write(text + "\n")

    print(f"kept {len(kept)} of {len(events)} events")
    for (name, who_), n in sorted(Counter((e["eventName"], who(e)) for e in kept).items()):
        print(f"  {name:26} {str(who_):18} x{n}")
    missing = {k: v for k, v in left.items() if v > 0}
    if missing:
        print("not found (fewer events than expected):", missing)
    return 0


if __name__ == "__main__":
    sys.exit(main())