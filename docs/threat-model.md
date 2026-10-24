# Threat model

Two questions: what is ShiftGuard trying to protect against, and what can go wrong with ShiftGuard itself.

## What it defends against

An attacker (or a careless insider) who already has some AWS identity and wants admin through IAM permissions alone. They have no exploit and no vulnerability, only permissions that were granted too widely. The attack techniques are the 13 listed in the README.

**Where ShiftGuard helps:**
- Before deploy: finds the path in the Terraform plan so a pull request can be stopped.
- After deploy: gives a Sigma rule to detect the abuse in CloudTrail, where one exists.

## Assets

| Asset | Why it matters |
|---|---|
| Admin access to the AWS account | the thing an attacker wants |
| Terraform plan files | can contain sensitive values and a full map of your IAM |
| CloudTrail logs | the evidence. Stopping them is itself an attack (T1685.002) |
| The ShiftGuard rules and code | wrong rules give false confidence |

## Attacker model

- Has a valid low-privilege principal (a user or a role).
- Works only through IAM and STS API calls.
- Does not need network access to your CI.
- May try to hide by stopping logging.

Out of scope: stolen admin credentials, vulnerabilities in AWS itself, data-plane attacks (S3, databases), compromised CI, attacks through resource-based policies and SCPs that ShiftGuard does not read.

## Risks of using ShiftGuard

| Risk | What happens | What reduces it |
|---|---|---|
| **False negative** | a path exists but is not reported (a technique is missing, a path is longer than the one shortest path, a resource-based policy grants access) | the limits list in the README. A clean result is not a clean bill of health. |
| **False positive** | a path is reported but a Deny, Condition, permission boundary or SCP blocks it | the output shows exactly which permission is involved so a reviewer can check |
| **Weak detections** | a rule fires on normal admin work, or misses a real event because the field names differ from real CloudTrail | fixtures with benign events, and an honest "not verified" list for the field names |
| **Sensitive plan files** | a real plan JSON committed to git exposes IAM structure and possibly secrets | labs use fake data, `.gitignore`, Gitleaks in CI. Never commit real plans. |
| **Untrusted Sigma rules** | the matcher supports regex from a rule file. A hostile rule could use a slow regex | only run rules from this repo or sources you trust. Rules are loaded with `yaml.safe_load`. |
| **CI supply chain** | a compromised GitHub Action runs in the pipeline | `permissions: contents: read`. Actions are pinned to major version tags, not commit SHAs, which is weaker (TODO: pin SHAs) |
| **Gaps in detection** | techniques with no rule are invisible to CloudTrail alerts | listed openly in the output and in the Navigator layer in red |

## Trust boundaries

1. **Terraform plan to ShiftGuard.** The plan is treated as data. It is parsed as JSON only, nothing in it is executed.
2. **Sigma rules to matcher.** Rules are trusted repo content, not user input.
3. **CI to GitHub.** Read-only token, no secrets needed for the analyzer.

ShiftGuard makes no network calls, needs no cloud credentials and never applies Terraform.

## What an attacker could do against ShiftGuard

- Hide a path using something ShiftGuard does not understand (a technique not on the list, cross-account trust). The fix is more coverage, not trust.
- Edit the Terraform to look safe in the plan but differ after apply (for example through values only known at apply). Plan-time checks cannot fully stop this, which is why runtime detections matter.
- Remove the CI check. Branch protection requiring the check is the control for that, and is not part of this repo.

## Residual risk

ShiftGuard reduces one specific kind of risk and gives a start for detection. It does not replace a review by a person, an SCP and permission boundary strategy, or a tool that reads live accounts.