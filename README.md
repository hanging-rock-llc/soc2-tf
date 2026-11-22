# soc2-tf (`tfproof`)

**SOC 2 change-management evidence for Terraform and OpenTofu on GitHub Actions. You don't need a TACO for it.**

If your Terraform already runs in GitHub Actions with OIDC and S3 state, you're most of the way to passing a SOC 2 change-management audit. What's missing is the evidence: a tamper-evident record, for every production apply, of what changed, who approved it, whether that approver was independent of the author, and proof that what got applied is what got approved.

The usual way to get that is a Terraform Cloud-style platform priced for enterprises. `tfproof` is the missing piece by itself:

- **Captures** every plan and apply as a JSON record: the change set, the PR, the reviewers, any deployment-environment approvers, the AWS role session that ran it, and the exit code.
- **Verifies** before apply that the plan being applied is byte-for-byte the plan from earlier in the run, and that its planned changes (resources, actions and resulting values) match the last plan of the pull request's final commit. If not, it fails the job.
- **Stores** records write-once in **your** S3 bucket with Object Lock: a record can't be overwritten or deleted, and the report flags any record whose version history says otherwise.
- **Reports**: one command produces the change population (`changes.csv`) and an exceptions summary (`summary.md`) for your auditor.

It does not run Terraform, read your state, or hold credentials for your infrastructure. It's a single Go binary with **zero third-party dependencies**, and there's no server and no SaaS.

> Status: v0. The core flow is tested end to end against fake S3, STS and GitHub APIs. Run it in GOVERNANCE mode for a sprint before switching the bucket to COMPLIANCE.

## How it fits

```
pull_request ─▶ terraform plan ─▶ tfproof capture-plan ──────────────┐
                                                                     │   S3 (Object Lock)
push to main ─▶ terraform plan ─▶ tfproof capture-plan ──────────────┤   records/…  index/…
                     │                                               │
                     ▼  environment: production (main only)          │
               tfproof verify ──(fail = no apply)                    │
               terraform apply                                       │
               tfproof capture-apply ────────────────────────────────┘
                                                                     │
monthly / on demand ─▶ tfproof report ─▶ changes.csv + summary.md ◀──┘
```

Every step also writes a summary to the GitHub Actions run page (counts by action, the change list, approvers, verification result), which covers day-to-day visibility on plans and applies without another UI.

## Quick start

### 1. Create the evidence bucket

```hcl
module "tf_evidence" {
  source = "github.com/hanging-rock-llc/soc2-tf//terraform/modules/evidence-bucket"

  bucket_name           = "acme-tf-evidence"
  evidence_prefix       = "tfproof" # the path in s3://acme-tf-evidence/tfproof
  retention_mode        = "GOVERNANCE" # switch to COMPLIANCE once you're happy
  retention_days        = 400
  writer_principal_arns = [aws_iam_role.gha_plan.arn, aws_iam_role.gha_apply.arn]
}

# The plan role can write plan records and indexes; only the apply role can
# write apply records.
resource "aws_iam_role_policy" "plan_writes_evidence" {
  role   = aws_iam_role.gha_plan.id
  policy = module.tf_evidence.plan_writer_policy_json
}

resource "aws_iam_role_policy" "apply_writes_evidence" {
  role   = aws_iam_role.gha_apply.id
  policy = module.tf_evidence.apply_writer_policy_json
}

# Optional: CloudTrail data events for every read/write of your state bucket.
module "state_audit" {
  source           = "github.com/hanging-rock-llc/soc2-tf//terraform/modules/state-audit-trail"
  state_bucket_arn = "arn:aws:s3:::acme-tf-state"
  log_bucket_name  = "acme-tf-state-access-logs"
}
```

### 2. Add tfproof to your workflow

See [`examples/terraform.yml`](examples/terraform.yml) for the full plan → verify → apply workflow. The essential parts:

```yaml
permissions:
  id-token: write
  contents: read
  pull-requests: read   # PR reviews
  actions: read         # environment approvals, if your plan has them

# ...after terraform plan -out=tfplan
- uses: hanging-rock-llc/soc2-tf@<commit-sha>
  with:
    command: capture-plan
    sink: s3://acme-tf-evidence/tfproof
    workdir: infra/prod
    plan-file: tfplan

# ...in the apply job, before terraform apply
- uses: hanging-rock-llc/soc2-tf@<commit-sha>
  with:
    command: verify
    sink: s3://acme-tf-evidence/tfproof
    workdir: infra/prod
    plan-file: tfplan
    require-same-run: "true"
    require-pr: "true"

# ...after terraform apply (always, unless apply was skipped because verify failed)
- uses: hanging-rock-llc/soc2-tf@<commit-sha>
  if: always() && steps.apply.outcome != 'skipped'
  with:
    command: capture-apply
    sink: s3://acme-tf-evidence/tfproof
    workdir: infra/prod
    plan-file: tfplan
    exit-code: ${{ steps.apply.outputs.exit-code || '1' }}
    log: infra/prod/apply.log
    environment: production   # only approvals of this environment count
```

Set `role-session-name: gha-${{ github.run_id }}-${{ github.run_attempt }}` on `aws-actions/configure-aws-credentials` so each CloudTrail event traces back to a single run.

Records are keyed by workdir and Terraform workspace. If one workdir is planned more than one way in the same run (for example once per var file), give each a distinct `stack:` so their plans aren't compared with each other.

### Approvals

The pull request review is the change approval. tfproof records who approved which commit and flags the apply if nobody independent of the change's authors approved its final commit. Make GitHub enforce the same thing with branch protection (or a ruleset) on `main`:

- require at least one approving review
- dismiss stale approvals when new commits are pushed
- require approval of the most recent reviewable push (so whoever pushed last can't be the approver)
- require branches to be up to date before merging

Branch protection and rulesets on private repositories need GitHub Pro, Team or Enterprise. On GitHub Free with a private repo nothing stops an unreviewed merge; tfproof still records it and the report lists it as an exception.

Deployment environments with **required reviewers** add a second, deploy-time approval, but GitHub only offers them on public repositories or with GitHub Enterprise. When present, tfproof records them, and an independent environment approval also covers a PR approval that went stale. Without them, use the `production` environment for its deployment-branch restriction (main only, available on Pro and Team) and for scoping the apply role's OIDC trust; leave the reviewers off.

### 3. Generate the evidence pack

```bash
tfproof report --sink s3://acme-tf-evidence/tfproof --repo acme/infra \
  --since 2026-01-01 --until 2027-01-01 --out-dir evidence/
```

Or schedule it: [`examples/evidence-report.yml`](examples/evidence-report.yml).

`summary.md` flags any apply that had:

- no recorded approval
- no approver independent of the change's authors (the PR author and everyone who authored or pushed its commits; bots don't count)
- a PR approval on an older commit with no independent environment approval after it
- a plan that wasn't verified against, or didn't match, the reviewed plan
- a record whose content hash doesn't match, that was overwritten, or that is stored under the wrong key

## CLI

```
tfproof capture plan   --sink S --workdir D (--plan-file F | --plan-json J) [--binary tofu] [--stack N]
tfproof verify         --sink S --workdir D --plan-file F [--stack N] [--require-same-run] [--require-pr] [--pr auto|N|none]
tfproof capture apply  --sink S --workdir D --plan-file F --exit-code N [--stack N] [--log L] [--upload-log]
tfproof report         --sink S [--repo owner/repo] [--since YYYY-MM-DD] [--until YYYY-MM-DD] [--out-dir D]
```

Every flag has an environment-variable form (`--sink` → `TFPROOF_SINK`). The sink can be a local directory for trying it out:

```bash
go install github.com/hanging-rock-llc/soc2-tf/cmd/tfproof@latest
terraform plan -out=tfplan
tfproof capture plan --sink ./evidence --plan-file tfplan --no-aws-identity
tfproof verify       --sink ./evidence --plan-file tfplan
tfproof capture apply --sink ./evidence --plan-file tfplan --exit-code 0 --no-aws-identity
tfproof report       --sink ./evidence
```

AWS credentials come from the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` environment variables, which `aws-actions/configure-aws-credentials` sets. Locally, `eval "$(aws configure export-credentials --format env)"` does the same.

## Docs

- [SOC 2 control mapping](docs/soc2-mapping.md): what auditors ask for and which fields answer it
- [Record schema](docs/record-schema.md): the record fields, the object layout, and how to verify a record by hand with `jq`
- [Security](SECURITY.md)

## Supported workflows

| Pattern | Verification |
|---|---|
| Plan job → apply job in one run, apply job in a `production` environment (recommended) | `same_run_match` (exact plan file) + `pull_request_match` (planned values) |
| Plan and apply in one job after merge | `pull_request_match` |
| `workflow_dispatch` / manual | No PR, so approval can only come from environment required reviewers (public repos or Enterprise); otherwise every manual apply is reported as unapproved. Verification relies on same-run plans |

`pull_request_match` compares against the plan captured on a `pull_request` event for the PR's final commit. Require branches to be up to date before merging; otherwise main's plan includes changes the PR's plan didn't, and verification fails until the PR is re-planned.

The action is a thin wrapper around the binary. Other CI systems can call the binary directly, but pull request and approval evidence is only collected inside GitHub Actions for now.

## Roadmap

- Join `report` with CloudTrail to show every AWS API call each apply made
- Signed records via GitHub artifact attestations (Sigstore)
- Release binaries so the action doesn't build from source
- GitLab CI context
- Push summaries to Vanta and Drata

## License

Apache-2.0. Built by [Hanging Rock Consulting](https://github.com/hanging-rock-llc).
