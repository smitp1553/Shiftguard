# writes tests/fixtures/cloudtrail/*.json, one file per rule, one cloudtrail record per line
# run it with:  python tests/make_cloudtrail_fixtures.py
# each file has "malicious" events (the rule must fire) and "benign" near misses (it must stay quiet)
# the records use the real cloudtrail format. Account id and ips are the documentation examples, no real data.
import json
import uuid
from pathlib import Path

OUT = Path(__file__).parent / "fixtures" / "cloudtrail"
ACCOUNT = "123456789012"
n = 0


def user(name, uid):
    return {"type": "IAMUser", "principalId": uid, "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
            "accountId": ACCOUNT, "accessKeyId": "EXAMPLEKEYID" + uid[-6:], "userName": name}


def role_session(role, session):
    return {"type": "AssumedRole", "principalId": f"AROAEXAMPLE{role.upper()[:6]}:{session}",
            "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/{session}", "accountId": ACCOUNT,
            "accessKeyId": "EXAMPLEKEYID000099",
            "sessionContext": {"sessionIssuer": {"type": "Role", "principalId": f"AROAEXAMPLE{role.upper()[:6]}",
                                                 "arn": f"arn:aws:iam::{ACCOUNT}:role/{role}", "accountId": ACCOUNT,
                                                 "userName": role},
                               "attributes": {"creationDate": "2026-10-22T08:00:00Z", "mfaAuthenticated": "false"}}}


ALICE = user("dev-alice", "AIDAEXAMPLE000001")
BOB = user("dev-bob", "AIDAEXAMPLE000002")
DAVE = user("dev-dave", "AIDAEXAMPLE000004")
ROOT = {"type": "Root", "principalId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:root", "accountId": ACCOUNT, "accessKeyId": ""}
CI = role_session("ci-automation", "build-4821")

ADMIN_DOC = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'


def ev(source, name, who, params=None, resp=None, etype="AwsApiCall", read_only=False, extra=None):
    global n
    n += 1
    rec = {
        "eventVersion": "1.09",
        "userIdentity": who,
        "eventTime": f"2026-10-22T09:{n % 60:02d}:11Z",
        "eventSource": source,
        "eventName": name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.25",
        "userAgent": f"aws-cli/2.15.0 Python/3.11.6 Windows/10 exe/AMD64 prompt/off command/{source.split('.')[0]}.{name}",
        "requestParameters": params,
        "responseElements": resp,
        "requestID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"req-{n}")),
        "eventID": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"evt-{n}")),
        "readOnly": read_only,
        "eventType": etype,
        "managementEvent": True,
        "recipientAccountId": ACCOUNT,
        "eventCategory": "Management",
    }
    if extra:
        rec.update(extra)
    return rec


def iam(name, who, params=None, resp=None, read_only=False):
    return ev("iam.amazonaws.com", name, who, params, resp, read_only=read_only)


def login(who, mfa, result):
    extra = {"additionalEventData": {"LoginTo": "https://console.aws.amazon.com/console/home?state=hashArgs", "MobileVersion": "No", "MFAUsed": mfa}}
    if mfa == "Yes":
        extra["additionalEventData"]["MFAIdentifier"] = f"arn:aws:iam::{ACCOUNT}:mfa/{who.get('userName', 'device')}"
    if result == "Failure":
        extra["errorMessage"] = "Failed authentication"
    who = dict(who)
    who.pop("accessKeyId", None)
    return ev("signin.amazonaws.com", "ConsoleLogin", who, None, {"ConsoleLogin": result}, etype="AwsConsoleSignIn", extra=extra)


POL = f"arn:aws:iam::{ACCOUNT}:policy/dev-alice-policy"
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/main-trail"
KEY_RESP = lambda u: {"accessKey": {"userName": u, "accessKeyId": "EXAMPLEKEYID000123", "status": "Active",
                                    "createDate": "Oct 22, 2026 9:12:11 AM", "secretAccessKey": "HIDDEN_DUE_TO_SECURITY_REASONS"}}

cases = {
    "aws_iam_create_policy_version": (
        [iam("CreatePolicyVersion", ALICE, {"policyArn": POL, "policyDocument": ADMIN_DOC, "setAsDefault": True},
             {"policyVersion": {"versionId": "v2", "isDefaultVersion": True, "createDate": "Oct 22, 2026 9:12:11 AM"}})],
        [iam("CreatePolicyVersion", ALICE, {"policyArn": POL, "policyDocument": ADMIN_DOC, "setAsDefault": False},
             {"policyVersion": {"versionId": "v2", "isDefaultVersion": False, "createDate": "Oct 22, 2026 9:12:11 AM"}})],
    ),
    "aws_iam_set_default_policy_version": (
        [iam("SetDefaultPolicyVersion", ALICE, {"policyArn": POL, "versionId": "v1"})],
        [iam("ListPolicyVersions", ALICE, {"policyArn": POL}, None, read_only=True)],
    ),
    "aws_iam_attach_admin_policy": (
        [iam("AttachUserPolicy", BOB, {"userName": "dev-bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}),
         iam("AttachRolePolicy", CI, {"roleName": "app-role", "policyArn": "arn:aws:iam::aws:policy/IAMFullAccess"})],
        [iam("AttachUserPolicy", BOB, {"userName": "dev-bob", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
         iam("AttachUserPolicy", BOB, {"userName": "dev-bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess-Amplify"})],
    ),
    "aws_iam_put_admin_policy": (
        [iam("PutUserPolicy", BOB, {"userName": "dev-bob", "policyName": "temp", "policyDocument": ADMIN_DOC}),
         iam("PutRolePolicy", CI, {"roleName": "app-role", "policyName": "temp",
                                   "policyDocument": '{\n  "Version": "2012-10-17",\n  "Statement": [{"Effect": "Allow", "Action": [ "*" ], "Resource": "*"}]\n}'})],
        [iam("PutUserPolicy", BOB, {"userName": "dev-bob", "policyName": "reports",
                                    "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::example-reports-bucket/*"}]}'}),
         iam("PutUserPolicy", BOB, {"userName": "dev-bob", "policyName": "bucket-admin",
                                    "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::example-reports-bucket/*"}]}'})],
    ),
    "aws_iam_create_access_key_other_user": (
        [iam("CreateAccessKey", DAVE, {"userName": "admin-user"}, KEY_RESP("admin-user")),
         iam("CreateAccessKey", CI, {"userName": "admin-user"}, KEY_RESP("admin-user"))],
        [iam("CreateAccessKey", DAVE, {"userName": "dev-dave"}, KEY_RESP("dev-dave")),
         iam("CreateAccessKey", DAVE, None, KEY_RESP("dev-dave"))],
    ),
    "aws_iam_login_profile_other_user": (
        [iam("CreateLoginProfile", DAVE, {"userName": "admin-user", "password": "HIDDEN_DUE_TO_SECURITY_REASONS", "passwordResetRequired": False},
             {"loginProfile": {"userName": "admin-user", "createDate": "Oct 22, 2026 9:20:00 AM", "passwordResetRequired": False}}),
         iam("UpdateLoginProfile", DAVE, {"userName": "admin-user", "password": "HIDDEN_DUE_TO_SECURITY_REASONS"})],
        [iam("UpdateLoginProfile", ALICE, {"userName": "dev-alice", "password": "HIDDEN_DUE_TO_SECURITY_REASONS"})],
    ),
    "aws_iam_update_assume_role_policy": (
        [iam("UpdateAssumeRolePolicy", DAVE, {"roleName": "admin-role",
                                              "policyDocument": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/dev-dave"},"Action":"sts:AssumeRole"}]}'})],
        [iam("GetRole", DAVE, {"roleName": "admin-role"}, None, read_only=True)],
    ),
    "aws_cloudtrail_logging_changed": (
        [ev("cloudtrail.amazonaws.com", "StopLogging", BOB, {"name": TRAIL}),
         ev("cloudtrail.amazonaws.com", "DeleteTrail", BOB, {"name": TRAIL}),
         ev("cloudtrail.amazonaws.com", "UpdateTrail", BOB, {"name": "main-trail", "isMultiRegionTrail": False})],
        [ev("cloudtrail.amazonaws.com", "StartLogging", BOB, {"name": TRAIL}),
         ev("cloudtrail.amazonaws.com", "GetTrailStatus", BOB, {"name": TRAIL}, None, read_only=True)],
    ),
    "aws_console_login_no_mfa": (
        [login(ALICE, "No", "Success")],
        [login(ALICE, "Yes", "Success"),
         login(ALICE, "No", "Failure"),
         login(role_session("sso-readonly", "jane@example.com"), "No", "Success")],
    ),
    "aws_root_account_usage": (
        [iam("ListUsers", ROOT, None, None, read_only=True),
         login(ROOT, "Yes", "Success")],
        [iam("ListUsers", ALICE, None, None, read_only=True),
         ev("kms.amazonaws.com", "RotateKey", ROOT, None, None, etype="AwsServiceEvent")],
    ),
}

OUT.mkdir(parents=True, exist_ok=True)
for name, (bad, good) in cases.items():
    lines = ['{', '"malicious": [']
    lines += [json.dumps(r, separators=(",", ":")) + ("," if i < len(bad) - 1 else "") for i, r in enumerate(bad)]
    lines += ['],', '"benign": [']
    lines += [json.dumps(r, separators=(",", ":")) + ("," if i < len(good) - 1 else "") for i, r in enumerate(good)]
    lines += [']', '}']
    (OUT / f"{name}.json").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(len(cases), "fixture files written")
