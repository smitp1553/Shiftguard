# Detection coverage

What ShiftGuard can detect in AWS CloudTrail after an attacker abuses an IAM escalation path, and what it cannot.
The rules are in `detections/sigma/`. Each one has a test file of malicious and benign CloudTrail events in
`tests/fixtures/cloudtrail/`. Written 2026-10-22.

## The rules

| Rule file | What it catches | ATT&CK | Level |
|---|---|---|---|
| aws_iam_create_policy_version | CreatePolicyVersion with setAsDefault true | T1098.003 | high |
| aws_iam_set_default_policy_version | SetDefaultPolicyVersion | T1098.003 | medium |
| aws_iam_attach_admin_policy | AdministratorAccess or IAMFullAccess attached to a user, role or group | T1098.003 | high |
| aws_iam_put_admin_policy | inline policy with Action * on Resource * written | T1098.003 | high |
| aws_iam_create_access_key_other_user | access key created for a different user than the caller | T1098.001 | high |
| aws_iam_login_profile_other_user | console password set for a different user than the caller | T1098.001 | high |
| aws_iam_update_assume_role_policy | role trust policy rewritten | T1098.003 | high |
| aws_cloudtrail_logging_changed | StopLogging, DeleteTrail, UpdateTrail | T1685.002 | high |
| aws_console_login_no_mfa | IAM user console login without MFA | T1078.004 | medium |
| aws_root_account_usage | any root user activity (AWS service events removed) | T1078.004 | high |

## Which escalation techniques have a detection

| ShiftGuard technique | Detected by | Notes |
|---|---|---|
| CreatePolicyVersion | aws_iam_create_policy_version | if setAsDefault is false, the follow-up SetDefaultPolicyVersion is caught by the next rule |
| SetDefaultPolicyVersion | aws_iam_set_default_policy_version | |
| AttachUserPolicy | aws_iam_attach_admin_policy | partial: only the two AWS managed admin policies, not custom ones that are admin in practice |
| AttachRolePolicy | aws_iam_attach_admin_policy | same limit |
| PutUserPolicy | aws_iam_put_admin_policy | partial: only Action * on Resource * |
| PutRolePolicy | aws_iam_put_admin_policy | same limit |
| CreateAccessKey | aws_iam_create_access_key_other_user | |
| CreateLoginProfile | aws_iam_login_profile_other_user | also covers UpdateLoginProfile |
| UpdateAssumeRolePolicy | aws_iam_update_assume_role_policy | |
| AddUserToGroup | not covered | needs to know which groups are admin groups. That knowledge is in the Terraform plan, not in the event |
| AssumeRole | not covered | very high volume. A useful rule needs a baseline of normal role use |
| PassRole + RunInstances | not covered | as far as I know PassRole is a permission check and not a CloudTrail event, so the rule would have to watch RunInstances with an instance profile. Verify this in the AWS docs before relying on it |
| PassRole + Lambda | not covered | same reason, for CreateFunction |

9 of the 13 techniques have a rule, 4 do not. The 3 extra rules (trail changes, no-MFA login, root usage) are not escalation techniques.

## Portability (checked with pySigma 1.5.1)

| | Splunk | Elastic ESQL | Elastic Lucene |
|---|---|---|---|
| 8 rules without field comparison | converts | converts | converts |
| aws_iam_create_access_key_other_user | converts | converts | cannot, Lucene cannot compare two fields of one event |
| aws_iam_login_profile_other_user | converts | converts | cannot, same reason |

`sigma check` found 0 issues with 30 validators. The two validators that download MITRE data (attacktag and d3_fendtag)
could not run in my build environment, so run the full `sigma check detections/sigma` on a machine with internet.

## How the rules were tested

1. Hand-designed CloudTrail events in the real record format: for every rule, malicious events that must fire it and benign near misses
   that must not (for example setAsDefault false, a key created for your own user, AdministratorAccess-Amplify).
   No benign event fires any rule.
2. I broke the rules and the matcher on purpose in six ways (wrong value, endswith turned into contains, removed filter,
   `not` ignored, escaped star treated as a wildcard, removed condition part). The tests failed every time.
3. The trail rule was run on 3 real CloudTrail events from Splunk's attack_data sample "stop_delete_cloudtrail".
   It fired on all 3. I did not commit that data, because I could not confirm its license.

## Known limits and false positives

- Only CloudTrail management events are covered. Data events and other log sources are not.
- The rules look at what happened, not whether it was allowed. Failed attempts (AccessDenied) also match, on purpose.
- Roles that create keys or passwords have no userIdentity.userName, so every such event matches the two "different user" rules. Allow-list your automation roles.
- Federated and single sign-on logins record MFAUsed as No even when the identity provider enforced MFA. The no-MFA rule only checks IAM users for that reason, so federated users without MFA are missed.
- The admin policy rules recognise only the obvious cases. A custom policy with iam:* or a long action list is not matched.
- There is no correlation yet (for example access key created, then used from a new IP within an hour).

## Not verified yet

- The names of the request parameters (setAsDefault, policyArn, userName, policyDocument) follow the IAM API reference and the CloudTrail naming
  convention. I confirmed the trail events and the ConsoleLogin fields against real data and AWS docs, but I have not seen a real IAM event for the
  other rules. Verify with CloudTrail Event History in your own AWS account, or with another public dataset, before you claim they work on real logs.
- The AwsServiceEvent filter in the root rule follows the SigmaHQ convention. I did not find a real sample of a root service event.


## ATT&CK version note

ATT&CK v19 (April 2026) split the Defense Evasion tactic into Stealth and Defense Impairment, and revoked
T1562.008 "Disable or Modify Cloud Logs". Its replacement is T1685.002 "Disable or Modify Cloud Log" (under T1685
"Disable or Modify Tools"), in the Defense Impairment tactic. The trail rule uses the new tags. I checked this on
MITRE's own pages and in the ATT&CK v20.0 data on 2026-10-22, and `sigma check` validates the tag strings.
