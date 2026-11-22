# SOC 2 control mapping

How tfproof's evidence lines up with the Trust Services Criteria auditors usually test for infrastructure-as-code changes. This is guidance, not legal or audit advice; agree the control wording with your auditor.

## CC8.1: Changes are authorized, tested, approved and implemented

Auditors typically pull the full population of production changes for the period, sample from it, and ask for proof of each control on every sampled change.

| What the auditor asks | tfproof evidence |
|---|---|
| Complete list of production infrastructure changes in the period | `changes.csv` from `tfproof report`: one row per apply, generated from immutable records rather than a hand-kept list |
| What changed | `plan.changes` and `plan.summary` in each record; the plan JSON hash (`plan.json_sha256`) |
| Who requested the change | `pull_request.author`, `pull_request.url` |
| Who approved it, and were they independent of the author | `approval.approved_by`, `approval.environment_approved_by`, `approval.independent_approver` |
| Was the approval for the final version of the change | `approval.approved_head` (approval was on the PR's final commit) |
| Was what got deployed the thing that was approved | `apply.verification`: the applied plan file is byte-identical to the plan from the same run (`same_run_match`), and its change set matches the last plan reviewed on the PR (`pull_request_match`) |
| Did it succeed | `apply.exit_code`, `apply.succeeded`, `apply.log_sha256` |
| Exceptions | `summary.md` lists every apply with a missing approval, a self-approval, a stale approval, or an unverified plan |

## CC6.1 / CC6.3: Logical access

| What the auditor asks | tfproof evidence |
|---|---|
| Production changes don't run under personal credentials | `cloud_identity.arn` / `role_name`: the CI role that applied |
| Access is short-lived and attributable | `cloud_identity.role_session_name`; set it to `gha-<run_id>-<attempt>` so every CloudTrail event maps to one run |

## CC7.2 / CC7.3: Monitoring and evidence integrity

| What the auditor asks | tfproof evidence |
|---|---|
| Logs can't be altered or deleted | Records live in an S3 Object Lock bucket (COMPLIANCE mode), written with SHA-256 checksums; `content_sha256` in each record can be recomputed independently |
| Access to Terraform state is logged | `terraform/modules/state-audit-trail`: CloudTrail data events on every state object read and write, with log file validation |
| Who wrote the evidence | The evidence bucket policy only lets the CI roles add records; nobody can delete them |

## What tfproof does not cover

- Branch protection and required-review settings themselves. Export these from GitHub (or your compliance platform) as configuration evidence.
- Changes made outside CI (console click-ops). Pair tfproof with drift detection and CloudTrail management-event monitoring so out-of-band changes surface as findings.
- Code review quality. tfproof proves a qualified person approved; it can't prove they read carefully.

## Retention

SOC 2 Type II observation windows are usually 6-12 months and the audit happens after the window closes. The module defaults to 400 days of Object Lock retention. If you're unsure, ask your auditor and set `retention_days` accordingly; in COMPLIANCE mode retention can't be shortened later.
