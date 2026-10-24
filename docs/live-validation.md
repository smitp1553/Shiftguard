# Live validation on a real AWS account

The rest of ShiftGuard works offline. This page records the one time it was checked against real AWS events, what that showed, and what it could not show.

## What was done

- A new AWS account on the Free plan (up to $200 in credits, no charge unless upgraded). Only IAM, STS and CloudTrail event history were used. All three are free, and no EC2, S3 or CloudTrail trail was created.
- `terraform/lab-live` creates 8 IAM users, 2 roles and 9 policies. Each test user can do exactly one risky thing.
- Each user ran their attack from the AWS CLI. A few harmless "benign" calls were mixed in.
- The events were downloaded from CloudTrail event history (us-east-1) and run through the Sigma rules with `detections/matcher.py`.
- A cleaned copy (account id, key ids, IPs and error messages removed by `tools/sanitize_live_events.py`) is in `tests/fixtures/cloudtrail_real/` and is tested by `tests/test_real_events.py`.
- Everything was deleted afterwards and the keys were removed.

## Results

| Real event | Rule | Fired |
|---|---|---|
| CreatePolicyVersion (set as default) | aws_iam_create_policy_version | yes |
| SetDefaultPolicyVersion | aws_iam_set_default_policy_version | yes |
| AttachUserPolicy with AdministratorAccess | aws_iam_attach_admin_policy | yes |
| AttachUserPolicy with ReadOnlyAccess (benign) | aws_iam_attach_admin_policy | no, correct |
| PutUserPolicy with an admin document | aws_iam_put_admin_policy | yes |
| PutUserPolicy with a harmless document (benign) | aws_iam_put_admin_policy | no, correct |
| CreateAccessKey for another user | aws_iam_create_access_key_other_user | yes |
| CreateAccessKey by an assumed role (step 2 of the chain) | aws_iam_create_access_key_other_user | yes (in the local matcher, see below) |
| UpdateAssumeRolePolicy | aws_iam_update_assume_role_policy | yes |
| CreateLoginProfile | aws_iam_login_profile_other_user | not tested, see below |
| Console sign-in | aws_root_account_usage, aws_console_login_no_mfa | not tested, see below |

## What the real events taught me

1. **The IAM field names I took from the documentation matched** for the six rules above (`requestParameters.policyArn`, `setAsDefault`, `userName` and the policy document).
2. **A denied call is logged without request parameters.** A `CreateAccessKey` by dev-dave on his own user was denied and had no `requestParameters`; the denied `CreateLoginProfile` also had none. Rules that look at request fields cannot fire on failed attempts. Detecting repeated `AccessDenied` on IAM calls would need a separate rule. This is based on the denied events I saw, not a full survey.
3. **An administrator creating keys for others fires the key rule every time.** The seven keys I created for the test users, made by my own admin user, all fired it. That is a correct match and a false-positive source in a real company, where the rule needs an allow-list for the people and automation that are supposed to do this.
4. **An assumed role has no `userIdentity.userName`.** The key rule compares `requestParameters.userName` with the caller's `userName`. It fired for the assumed role in my matcher, which treats a missing field as "different". Splunk and ES|QL may treat a comparison with a missing value as null and drop the event. I believe this but have not tested it, because I had no Splunk or Elasticsearch to run it on.
5. **The account sits under a guardrail I cannot see.** An AWS service control policy denied `iam:CreateLoginProfile` and denied CloudTrail lookups in some regions. I did not try to get around it. It is a live example of the limit in the README: ShiftGuard does not read SCPs, so it would report a login-profile path that the SCP blocks.
6. **The sign-ins in this account were `AssumedRole`, not `Root` or `IAMUser`.** The root rule and the no-MFA rule correctly stayed quiet, and neither was tested on a matching real event. The no-MFA rule only covers IAM users, so it would not catch an assumed-role sign-in without MFA.

## What this does not show

- One account, one day, events created from the AWS CLI. The console or an SDK may log slightly different fields.
- Not tested on real events: `aws_iam_login_profile_other_user` (blocked by the SCP), `aws_root_account_usage`, `aws_console_login_no_mfa`, `aws_cloudtrail_logging_changed` (no trail was created, to avoid cost; it was tested earlier on 3 events from the Splunk attack_data project).
- PassRole was not tested because it needs EC2.
- The Splunk and ES|QL conversions were checked for syntax only, never run on a real system.
## Cleanup note

terraform destroy removed the roles, policies and keys but stopped at the users, because the AWS guardrail denies iam:DeleteLoginProfile (which force_destroy calls first). The users had no console password, so they were deleted with aws iam delete-user instead. The credit balance was still 100 USD after the test (usage data can lag).

