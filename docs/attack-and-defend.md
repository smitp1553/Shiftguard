# Attack and defend

For each path ShiftGuard finds in the labs: what the attacker does, what CloudTrail should record, which Sigma rule catches it, and how to fix it.

Only try these in an AWS account you own. The labs here are never applied, so none of this has been run for real. The CloudTrail details come from the AWS documentation and are listed as not verified in the README.

## 1. dev-alice: CreatePolicyVersion

**Attack.** Alice can write new versions of her own policy. She writes a version that allows everything and makes it the default.


**In CloudTrail.** `eventSource` iam.amazonaws.com, `eventName` CreatePolicyVersion, `requestParameters.setAsDefault` true.
**Detect.** `aws_iam_create_policy_version` (T1098.003).
**Fix.** Remove `iam:CreatePolicyVersion`, or limit it to policies not attached to the same principal.

## 2. dev-bob: AttachUserPolicy

**Attack.** Bob can attach any managed policy to a user, including himself.


**In CloudTrail.** AttachUserPolicy with `requestParameters.policyArn` ending in `:policy/AdministratorAccess`.
**Detect.** `aws_iam_attach_admin_policy` (T1098.003).
**Fix.** Remove `iam:AttachUserPolicy`, or scope the resource so he cannot target his own user.

## 3. dev-carol: PassRole + RunInstances

**Attack.** Carol can start an EC2 instance and pass it an admin role. She then reads the role's temporary credentials from inside the instance and uses them. (The lab does not include an instance profile, so this is the idea, not a working command.)

**In CloudTrail.** The instance start is a RunInstances event. As far as I know, PassRole is not logged as its own event (not verified).
**Detect.** No rule. This is a documented gap. A detection would need to look at RunInstances with an instance profile, or at the use of the role from an unexpected place.
**Fix.** Limit `iam:PassRole` to specific low-privilege role ARNs and add an `iam:PassedToService` condition (ShiftGuard does not read conditions yet).

## 4. dev-dave: CreateAccessKey

**Attack.** Dave can create access keys for any user, including the admin user. He then uses those keys.


**In CloudTrail.** An AssumeRole event on sts.amazonaws.com.
**Detect.** No rule. AssumeRole happens constantly in normal traffic, so a rule on it alone would be noise. The better place to detect is when the trust policy is changed (`aws_iam_update_assume_role_policy`).
**Fix.** Narrow the trust policy to the exact principals that need it.

## 6. dev-gina: the two-step chain (lab-chain)

**Attack.** Step 1: gina assumes `key-manager-role`. Step 2: that role creates an access key for `admin-user`.


**In CloudTrail.** An AssumeRole event, then a CreateAccessKey where the caller is the role session, not the target user.
**Detect.** Step 1 has no rule. Step 2 is caught by `aws_iam_create_access_key_other_user`. So even though the first step is invisible, the chain is still detected at its last step.
**Fix.** Do not let `key-manager-role` create keys for admin users. Scope its `iam:CreateAccessKey` to ordinary users only.
**Why this one matters.** Both policies look small. Checkov's default escalation checks passed both. Only the chain shows the problem.

## What this tells you

- 4 of the 6 paths have a rule at the step that matters. 2 do not (carol, erin), and the gap is listed.
- Detection is the second line. The first line is the fix. Every fix above removes a permission, so no rule is needed once it is applied.
- A detection that fires is only useful if somebody looks at it. ShiftGuard does not handle alert routing.