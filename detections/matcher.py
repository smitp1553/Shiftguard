import json
import re
import sys
from pathlib import Path

import yaml

# a tiny Sigma matcher. It only knows the part of Sigma that my rules use.
# TODO: keyword searches, cidr, base64 and the other modifiers are not supported (it stops with an error)

KNOWN_MODIFIERS = ["contains", "startswith", "endswith", "re", "all", "exists", "fieldref"]


def load_rule(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_rules(folder):
    rules = []
    for path in sorted(Path(folder).glob("*.yml")):
        rules.append(load_rule(path))
    return rules


def get_field(event, name):
    # "requestParameters.userName" means event["requestParameters"]["userName"]
    value = event
    for part in name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def to_text(value):
    # sigma compares text without caring about upper or lower case
    # str(True) is "True", so a rule value of true and an event value of true both end up as "true"
    return str(value).lower()


def wildcard_to_regex(pattern):
    # in a sigma value * means anything and ? means one character.
    # a backslash in front turns them into normal characters (\* is a real star)
    out = ""
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern) and pattern[i + 1] in "*?\\":
            out += re.escape(pattern[i + 1])
            i += 2
            continue
        if c == "*":
            out += ".*"
        elif c == "?":
            out += "."
        else:
            out += re.escape(c)
        i += 1
    return out


def value_matches(event_value, rule_value, modifiers):
    # one event value against one value from the rule
    if "re" in modifiers:
        return re.search(str(rule_value), str(event_value)) is not None

    if rule_value is None:
        return event_value is None

    pattern = wildcard_to_regex(to_text(rule_value))
    text = to_text(event_value)
    if "contains" in modifiers:
        pattern = ".*" + pattern + ".*"
    elif "startswith" in modifiers:
        pattern = pattern + ".*"
    elif "endswith" in modifiers:
        pattern = ".*" + pattern
    return re.fullmatch(pattern, text, flags=re.DOTALL) is not None


def field_matches(event, key, wanted):
    parts = key.split("|")
    field = parts[0]
    modifiers = parts[1:]

    for m in modifiers:
        if m not in KNOWN_MODIFIERS:
            raise ValueError(f"modifier |{m} is not supported by my matcher")

    value = get_field(event, field)

    if "exists" in modifiers:
        return (value is not None) == bool(wanted)

    if "fieldref" in modifiers:
        # compare with another field of the same event
        other = get_field(event, wanted)
        return value is not None and other is not None and to_text(value) == to_text(other)

    if value is None and wanted is not None:
        return False

    if not isinstance(wanted, list):
        wanted = [wanted]

    results = [value_matches(value, w, modifiers) for w in wanted]
    if "all" in modifiers:
        return all(results)
    return any(results)  # a list of values means "this one or that one"


def selection_matches(event, selection):
    if isinstance(selection, list):
        if selection and not isinstance(selection[0], dict):
            raise ValueError("keyword selections are not supported by my matcher")
        # a list of maps means any map can match
        return any(selection_matches(event, s) for s in selection)

    # all fields in the map must match
    return all(field_matches(event, key, wanted) for key, wanted in selection.items())


# ---- the condition line ----
# grammar (the lowest binding first):  or  ->  and  ->  not  ->  name | ( or ) | 1 of x | all of x

def tokenize(text):
    return re.findall(r"\(|\)|[^\s()]+", text)


class Condition:
    def __init__(self, text, selections):
        self.tokens = tokenize(text)
        self.pos = 0
        self.selections = selections
        self.names = list(selections.keys())

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    # each parse function returns a function that takes the event and gives True or False
    def parse(self):
        result = self.parse_or()
        if self.peek() is not None:
            raise ValueError("unexpected '" + self.peek() + "' in condition")
        return result

    def parse_or(self):
        left = self.parse_and()
        while self.peek() == "or":
            self.take()
            right = self.parse_and()
            left = (lambda a, b: lambda e: a(e) or b(e))(left, right)
        return left

    def parse_and(self):
        left = self.parse_not()
        while self.peek() == "and":
            self.take()
            right = self.parse_not()
            left = (lambda a, b: lambda e: a(e) and b(e))(left, right)
        return left

    def parse_not(self):
        if self.peek() == "not":
            self.take()
            inner = self.parse_not()
            return lambda e: not inner(e)
        return self.parse_atom()

    def parse_atom(self):
        token = self.take()

        if token == "(":
            inner = self.parse_or()
            if self.peek() != ")":
                raise ValueError("missing )")
            self.take()
            return inner

        if token in ("1", "all") and self.peek() == "of":
            self.take()  # the word "of"
            pattern = self.take()
            names = self.names if pattern == "them" else [n for n in self.names if re.fullmatch(pattern.replace("*", ".*"), n)]
            if not names:
                raise ValueError("no selection matches " + pattern)
            tests = [self.name_test(n) for n in names]
            if token == "all":
                return lambda e: all(t(e) for t in tests)
            return lambda e: any(t(e) for t in tests)

        return self.name_test(token)

    def name_test(self, name):
        if name not in self.selections:
            raise ValueError("condition uses '" + name + "' but there is no such selection")
        selection = self.selections[name]
        return lambda e: selection_matches(e, selection)


def rule_matches(rule, event):
    detection = rule["detection"]
    selections = {k: v for k, v in detection.items() if k not in ("condition", "timeframe")}
    # TODO: a condition given as a list of lines is not supported
    test = Condition(detection["condition"], selections).parse()
    return test(event)


def scan(rules, events):
    # returns a list of (rule title, rule id, event) for every hit
    hits = []
    for event in events:
        for rule in rules:
            if rule_matches(rule, event):
                hits.append((rule["title"], rule["id"], event))
    return hits


def load_events(path):
    # a real cloudtrail file looks like {"Records": [ ... ]}, a plain list also works,
    # and some datasets have one json event per line
    with open(path, encoding="utf-8") as f:
        text = f.read()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    if isinstance(data, dict):
        return data.get("Records", [data])  # a single event has no Records key
    return data


def main():
    if len(sys.argv) != 3:
        print("usage: python -m detections.matcher detections/sigma events.json")
        return 2

    rules = load_rules(sys.argv[1])
    events = load_events(sys.argv[2])
    hits = scan(rules, events)

    for title, rule_id, event in hits:
        who = event.get("userIdentity", {}).get("arn", "?")
        print(f"HIT: {title} ({rule_id})  event={event.get('eventName')}  by={who}")
    print(f"{len(hits)} hits in {len(events)} events")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
