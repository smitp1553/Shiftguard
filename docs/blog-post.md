# Checkov passed my IAM policies. A two-step chain still reached admin.

*Draft. I'm a cybersecurity student, and this is a write-up of a portfolio project, not a research result.*

## The idea

Most IaC scanners judge one resource at a time. A policy that allows `sts:AssumeRole` on one role looks harmless. A role that can create an access key for one user looks scoped. But the two together are a path to admin, and no single resource shows it.

I built ShiftGuard to test that idea. It reads a Terraform plan (as JSON, never applied), builds a graph of who can become whom, and reports every principal that can reach admin. For each step it points to a Sigma detection rule for CloudTrail and an ATT&CK technique.

## How it works, briefly

1. Parse the plan JSON, including values that are unknown until apply (resolved through the configuration references).
2. Build an IAM graph: users, roles, groups, policies.
3. Run 13 hand-written techniques (CreatePolicyVersion, AttachUserPolicy, CreateAccessKey, AssumeRole and others). Each one adds edges "A can become B in one step".
4. Find the cheapest path to admin with a shortest-path search.

It exits with code 1 if a path is found, so it can fail a pull request.

## The test

I made three small labs, each with fake credentials and no AWS account:

- **lab-vulnerable:** five people with five different single-step escalations.
- **lab-safe:** the same people with the permissions fixed.
- **lab-chain:** one person with a two-step chain, where each policy looks small on its own.

Then I ran ShiftGuard and Checkov (3.3.30, default checks) on all three.

| Lab | ShiftGuard | Checkov escalation checks |
|---|---|---|
| vulnerable | 5 of 9 principals reach admin | flags all 5 |
| safe | 0 | 0 (18 hygiene failures, not about escalation) |
| chain | 2 of 3 reach admin | 0 |

## What I learned

**Checkov is better than I expected.** Its `CKV_AWS_286` ("policy allows privilege escalation") caught all the single-step cases and stayed quiet on the fixed versions. My first version of the comparison counted any Checkov failure as a catch, which made Checkov look better than it was, because it also fails 18 unrelated checks on the safe lab. I changed it to count only escalation checks and to say what the rest was.

**The gap is the chain.** In the chain lab, both policies passed Checkov's escalation checks, and ShiftGuard reported two steps to admin. One caveat matters: I built that lab to test exactly this gap. It shows the gap exists. It does not show that chains are common in real accounts, and Checkov supports custom checks that I did not try.

**Detection coverage is its own problem.** Every finding says which Sigma rule would catch it. 9 of the 13 techniques have a rule. PassRole and AssumeRole do not, and the output says so. AssumeRole is too common to alert on alone, and I believe PassRole is not logged as its own CloudTrail event (I haven't confirmed that). For the chain, the first step has no rule, but the second is caught.

**Standards move.** `sigma check` flagged my CloudTrail rule because MITRE ATT&CK v19 and v20 split Defense Evasion and revoked T1562.008 in favour of T1685.002. I added a test so an old tag cannot come back.

## What it does not do

No explicit Deny, Conditions, permission boundaries, SCPs or resource-based policies. Only 13 techniques. One shortest path per principal. Terraform and AWS only. It has never touched a real account. A clean result means "none of these 13 paths", not "safe". The README has the full list, including what I have not verified.

## What I would do next

- Run the labs in a throwaway AWS account to check the CloudTrail field names in the rules against real events.
- Read Conditions and permission boundaries.
- Write a rule for PassRole once I have confirmed what CloudTrail records.
- Pin the GitHub Actions to commit SHAs.

Code and docs: github.com/smitp1553/Shiftguard