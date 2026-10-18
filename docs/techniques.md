# Escalation techniques covered by ShiftGuard

| Technique | Needs | What it lets an attacker do | Severity | ATT&CK |
|---|---|---|---|---|
| CreatePolicyVersion | iam:CreatePolicyVersion | write a new default version of a policy attached to you, so you give yourself admin | HIGH | T1098.003 |
| AttachUserPolicy | iam:AttachUserPolicy | attach AdministratorAccess to your own user | HIGH | T1098.003 |
| PutUserPolicy | iam:PutUserPolicy | write an inline admin policy on your own user | HIGH | T1098.003 |
| AttachRolePolicy | iam:AttachRolePolicy, sts:AssumeRole | attach AdministratorAccess to a role you can assume, then assume it | HIGH | T1098.003 |
| PutRolePolicy | iam:PutRolePolicy, sts:AssumeRole | write an inline admin policy on a role you can assume, then assume it | HIGH | T1098.003 |
| AddUserToGroup | iam:AddUserToGroup | add your own user to a group that has admin permissions | HIGH | T1098.003 |
| SetDefaultPolicyVersion | iam:SetDefaultPolicyVersion | switch a policy attached to you back to an older, more permissive version | MEDIUM | T1098.003 |
| AssumeRole | sts:AssumeRole | assume a role whose trust policy lets you in | HIGH | T1548.005 |
| CreateAccessKey | iam:CreateAccessKey | create an access key for another user and act as them | HIGH | T1098.001 |
| CreateLoginProfile | iam:CreateLoginProfile or iam:UpdateLoginProfile | set a console password for another user and log in as them | HIGH | T1098.001 |
| PassRole+RunInstances | iam:PassRole, ec2:RunInstances | launch an EC2 instance that runs as a more powerful role, then read its credentials | HIGH | T1548.005 |
| PassRole+Lambda | iam:PassRole, lambda:CreateFunction, lambda:InvokeFunction | create a Lambda function with a more powerful role and invoke it to run code as that role | HIGH | T1548.005 |
| UpdateAssumeRolePolicy | iam:UpdateAssumeRolePolicy | rewrite a role's trust policy to name yourself, then assume it | HIGH | T1098.003 |
