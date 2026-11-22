# Record schema (`tfproof.dev/record/v1`)

Each plan or apply produces one JSON record.

## Object layout

Relative to the sink prefix (e.g. `s3://acme-tf-evidence/tfproof/`):

```
records/plan/<owner>/<repo>/<yyyy>/<mm>/<dd>/<run_id>-<attempt>-<job>-plan-<unit>.json     plan records (write-once)
records/apply/<owner>/<repo>/<yyyy>/<mm>/<dd>/<run_id>-<attempt>-<job>-apply-<unit>.json   apply records (write-once)
records/apply/.../<same>.log                                                               apply log (only with --upload-log)
index/<owner>/<repo>/run/<run_id>/<unit>/plan.json                                         latest plan in a run
index/<owner>/<repo>/pr/<number>/<unit>/plan.json                                          latest plan of a PR (pull_request events only)
```

`<unit>` identifies the root module instance: the `--stack` name if given, otherwise the workdir (`infra/prod` → `infra__prod`), plus `@<workspace>` for a non-default Terraform workspace.

Records are written with `If-None-Match: *`, and the evidence bucket policy rejects any write under `records/` without it, so a record can't be replaced by a new version. The phase comes first in the key so the plan role can be limited to `records/plan/` and the apply role to `records/apply/`. `tfproof report` lists object versions and flags any record with more than one, any record hidden by a delete marker, and any record whose key doesn't match its content.

Index objects are replaced as new plans arrive. On a versioned Object Lock bucket every prior version is retained, so the history stays intact. Only a capture on a `pull_request` event updates a PR index; a plan on main never replaces what was reviewed.

## Fields

| Field | Description |
|---|---|
| `schema` | `tfproof.dev/record/v1` |
| `id` | `<run_id>-<attempt>-<job>-<phase>-<unit>` |
| `phase` | `plan` or `apply` |
| `captured_at` | UTC timestamp |
| `tool` | `{name, version}` |
| `iac` | `{binary, version, workdir, workspace, stack}` |
| `run` | GitHub Actions context: repository, workflow, job, run ID/attempt/URL, event, ref, sha, actor, triggering actor, environment, and `pr_head_sha` (for `pull_request` events, the PR commit that was planned) |
| `pull_request` | `{number, url, title, author, head_sha, base_ref, merged, merged_by, merge_commit_sha}` |
| `approval` | apply only. `change_authors` (PR author plus every commit author/committer), `approved_by` (latest review APPROVED), `approved_head`, `environment` and `environment_approved_by` (approvals of that environment only), `independent_approver` (a non-author, non-bot approved the final commit or the deployment), `stale_approval`, raw `reviews` and `environment_reviews` |
| `cloud_identity` | `{account, arn, role_name, role_session_name}` from `sts:GetCallerIdentity` |
| `plan` | `file_sha256` (binary plan), `json_sha256`, `terraform_version`, `summary` (create/update/delete/replace/read/forget/import/no_op counts), `has_changes`, `changes[]` (`address`, `kind`, `action`, `actions`), `changeset_digest`, `values_digest` |
| `apply` | `exit_code`, `succeeded`, `log_sha256`, `log_key`, `verification` |
| `apply.verification` | `checked`, `same_run_match`, `same_run_record`, `pull_request_match`, `pull_request_record`, `passed`, `notes[]` |
| `warnings` | anything tfproof couldn't collect (e.g. missing token permissions) |
| `content_sha256` | SHA-256 of the stored record bytes with this field's value set to `""` |

## Digests

`changeset_digest` is the SHA-256 of the sorted list of `(kind, address, action)` for every change except no-ops and data-source reads. It says *which* resources change and *how*, not to what.

`values_digest` adds each change's planned end state: `after`, `after_unknown` and `importing` from `show -json`, with object keys sorted. Prior state (`before`) is left out so drift alone doesn't cause a mismatch. This is the digest `pull_request_match` compares: an apply-on-merge plan matches the PR's plan only if it would produce the same values. Plan values (including sensitive ones) are only hashed, never stored.

`same_run_match` compares the exact binary plan file (`file_sha256`).

`pull_request_match` is true only when the PR index record was captured on a `pull_request` event in a different run, of the commit the PR was merged at, and its `values_digest` equals the applied plan's.

## Verifying a record by hand

A record is one line of compact JSON. The hash covers that line with the `content_sha256` value emptied:

```bash
aws s3 cp s3://acme-tf-evidence/tfproof/records/apply/acme/infra/2026/11/22/<id>.json r.json
want=$(jq -r .content_sha256 r.json)
got=$(sed -E 's/"content_sha256":"[0-9a-f]{64}"}$/"content_sha256":""}/' r.json | tr -d '\n' | sha256sum | cut -d' ' -f1)
[ "$want" = "$got" ] && echo intact || echo ALTERED
aws s3api list-object-versions --bucket acme-tf-evidence --prefix tfproof/records/apply/acme/infra/2026/11/22/<id>.json \
  --query 'length(Versions)'   # must be 1
```

`content_sha256` detects changed bytes. It isn't a signature: anyone able to write a record could compute a matching hash, which is why records are write-once and the version count matters.
