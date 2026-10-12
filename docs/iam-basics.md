# IAM basics (my notes for ShiftGuard)

## Principals
A principal is an identity that can do things in AWS.
- **User**: a person or program with long-term credentials (password, access keys).
- **Role**: an identity with no password. You temporarily become it by assuming it. Services like EC2 use roles too.
- **Group**: a bag of users. Policies attached to the group apply to every member.

## Policies
A policy is a JSON document. Each statement has:
- **Effect**: Allow or Deny
- **Action**: what can be done, like s3:GetObject or iam:CreateAccessKey
- **Resource**: what it can be done to, written as an ARN

There are two kinds that matter here:
- **Identity-based policy**: attached to a user, group or role. Answers "what can this principal do?"
- **Trust policy**: attached to a role. Answers "who is allowed to assume this role?"

A policy can be *managed* (a standalone object that can be attached to many principals) or *inline* (written directly into one principal).

## sts:AssumeRole
This is the action of temporarily becoming a role. It works only when two things are true:
1. the role's trust policy allows the caller, and
2. the caller's own permissions allow calling sts:AssumeRole.

A trust policy that names the account root (arn:aws:iam::ACCOUNT:root) means "anyone in this account", as long as their own policies allow the call.

## iam:PassRole
PassRole lets a principal hand a role to an AWS service. With ec2:RunInstances, a user can launch an instance that runs as a powerful role, then read that role's credentials from inside the instance. The user never assumed the role directly, but ends up with its power.

## Wildcards
`*` in Action or Resource means "everything". `iam:*` is every IAM action. `Resource: "*"` is every resource. Most escalation paths in my lab exist because of a wildcard in Resource.

## Escalation paths in my vulnerable lab
| User | Permission | Why it is dangerous |
|---|---|---|
| dev-alice | iam:CreatePolicyVersion + SetDefaultPolicyVersion on * | can rewrite the policy attached to herself to Action * / Resource * |
| dev-bob | iam:AttachUserPolicy on * | can attach AdministratorAccess to himself |
| dev-carol | iam:PassRole + ec2:RunInstances on * | can launch an instance running as ec2-admin-role |
| dev-dave | iam:CreateAccessKey on * | can make access keys for admin-user and act as them |
| open-admin-role | trust policy names the account root | any principal in the account that may call sts:AssumeRole can become admin |
| dev-frank | s3:GetObject on one bucket | harmless, no path (the tool must not flag him) |

## How the safe lab fixes each one
- alice, bob: removed the IAM permissions, kept only what the job needs.
- carol: PassRole limited to one low-privilege role. TODO: also add an iam:PassedToService condition.
- dave: CreateAccessKey limited to his own user ARN.
- admin role: trust policy names only admin-user instead of the whole account.

## What I do not cover yet
Explicit Deny, Conditions, permission boundaries, SCPs, resource-based policies. These can all block or allow things my v1 tool will not see.
