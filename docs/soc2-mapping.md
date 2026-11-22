# SOC 2 control mapping

How tfproof's evidence lines up with the Trust Services Criteria auditors usually test for infrastructure-as-code changes. This is guidance, not legal or audit advice; agree the control wording with your auditor.

## CC8.1: Changes are authorized, tested, approved and implemented

Auditors typically pull the full population of production changes for the period, sample from it, and ask for proof of each control on every sampled change.

| What the auditor asks | tfproof evidence |
|---|---|
| Complete list of production infrastructure changes in the period | `changes.csv` from `tfproof report`: one row per apply recorded by `tfproof capture apply` that changed something, generated from write-once records rather than a hand-kept list. Applies made without tfproof aren't in it; reconcile with CloudTrail (see below) |
| What changed | `plan.changes` and `plan.summary` in each record; the plan JSON hash (`plan.json_sha256`) |
| Who requested the change | `pull_request.author`, `pull_request.url` |
| Who approved it, and were they independent of the author | `approval.approved_by`, `approval.environment_approved_by`, `approval.independent_approver` (someone other than the PR author and the authors/committers of its commits, not a bot, approved the final commit or the deployment) |
| Was the approval for the final version of the change | `approval.approved_head` (approval was on the PR's final commit); `approval.stale_approval` flags approvals that only cover earlier commits |
| Was what got deployed the thing that was approved | `apply.verification`: the applied plan file is byte-identical to the plan from the same run (`same_run_match`), and its planned resources, actions and values match the plan captured on the PR's final commit (`pull_request_match`) |
| Did it succeed | `apply.exit_code`, `apply.succeeded`, `apply.log_sha256` |
| Exceptions | `summary.md` lists every apply with a missing approval, no independent approver, a stale approval, an unverified plan, or a record that was altered or overwritten |

## CC6.1 / CC6.3: Logical access

| What the auditor asks | tfproof evidence |
|---|---|
| Production changes don't run under personal credentials | `cloud_identity.arn` / `role_name`: the CI role that applied |
| Access is short-lived and attributable | `cloud_identity.role_session_name`; set it to `gha-<run_id>-<attempt>` so every CloudTrail event maps to one run |

## CC7.2 / CC7.3: Monitoring and evidence integrity

| What the auditor asks | tfproof evidence |
|---|---|
| Logs can't be altered or deleted | Records are written once (`If-None-Match`, enforced by the bucket policy) to an S3 Object Lock bucket (COMPLIANCE mode) with SHA-256 checksums, and signed with a per-phase KMS key. `tfproof report` flags any record with more than one version, a delete marker, a `content_sha256` that doesn't match, or a missing or invalid signature |
| Access to Terraform state is logged | `terraform/modules/state-audit-trail`: CloudTrail data events on every state object read and write, with log file validation |
| Who wrote the evidence | The bucket policy lets only the CI roles add objects; the plan role can only write and sign plan records and indexes, the apply role only apply records; nobody can delete them. Every signing call is in CloudTrail with the run's role session |
| What did the change actually do in AWS | `tfproof report --cloudtrail`: `api-calls.csv` lists every AWS API call each apply's role session made, with errors; `changes.csv` has per-apply totals |

## What tfproof does not cover

- Branch protection and required-review settings themselves. Export these from GitHub or GitLab (or your compliance platform) as configuration evidence.
- Changes made outside CI (console click-ops), or applies from a workflow that doesn't run tfproof. Pair tfproof with drift detection and CloudTrail management-event monitoring so out-of-band changes surface as findings.
- Fabricated records from someone who can assume a CI role. Signing ties each record to a role's KMS key, but whoever can assume the apply role can sign as it (they can't replace or delete an existing record). Restrict the apply role's OIDC trust to a `production` environment that only `main` can deploy to.
- Enforcing review. tfproof records and reports approvals; the code host enforces them (GitHub branch protection on Pro, Team or Enterprise for private repos; GitLab approval rules on Premium). Deploy-time approval through environment required reviewers is only available on GitHub public repos or Enterprise, or GitLab Premium protected environments; without it, the PR/MR review is the approval.
- Code review quality. tfproof proves a qualified person approved; it can't prove they read carefully.

## Retention

SOC 2 Type II observation windows are usually 6-12 months and the audit happens after the window closes. The module defaults to 400 days of Object Lock retention. If you're unsure, ask your auditor and set `retention_days` accordingly; in COMPLIANCE mode retention can't be shortened later.
