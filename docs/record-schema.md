# Record schema (`tfproof.dev/record/v1`)

Each plan or apply produces one JSON record.

## Object layout

Relative to the sink prefix (e.g. `s3://acme-tf-evidence/tfproof/`):

```
records/plan/<owner>/<repo>/<yyyy>/<mm>/<dd>/<run_id>-<attempt>-<job>-plan-<unit>.json     plan records (write-once)
records/apply/<owner>/<repo>/<yyyy>/<mm>/<dd>/<run_id>-<attempt>-<job>-apply-<unit>.json   apply records (write-once)
records/apply/.../<same>.log                                                               apply log (only with --upload-log)
records/<phase>/.../<same>.sig                                                             KMS signature (only with --kms-key-id)
index/<owner>/<repo>/run/<run_id>/<unit>/plan.json                                         latest plan in a run
index/<owner>/<repo>/pr/<number>/<unit>/plan.json                                          latest plan of a PR/MR (pull_request / merge_request_event only)
```

`<unit>` identifies the root module instance: the `--stack` name if given, otherwise the workdir (`infra/prod` → `infra__prod`), plus `@<workspace>` for a non-default Terraform workspace.

Records are written with `If-None-Match: *`, and the evidence bucket policy rejects any write under `records/` without it, so a record can't be replaced by a new version. The phase comes first in the key so the plan role can be limited to `records/plan/` and the apply role to `records/apply/`. `tfproof report` lists object versions and flags any record with more than one, any record hidden by a delete marker, and any record whose key doesn't match its content.

Index objects are replaced as new plans arrive. On a versioned Object Lock bucket every prior version is retained, so the history stays intact. Only a capture on a `pull_request` (GitHub) or `merge_request_event` (GitLab) pipeline updates a PR index; a plan on main never replaces what was reviewed.

## Fields

| Field | Description |
|---|---|
| `schema` | `tfproof.dev/record/v1` |
| `id` | `<run_id>-<attempt>-<job>-<phase>-<unit>` |
| `phase` | `plan` or `apply` |
| `captured_at` | UTC timestamp |
| `tool` | `{name, version}` |
| `iac` | `{binary, version, workdir, workspace, stack}` |
| `run` | CI context: `provider` (`github-actions`, `gitlab-ci` or `local`), repository (`owner/repo`, GitLab project path), workflow, job, run ID/attempt/URL (GitLab: pipeline ID, job ID, pipeline URL), event (GitLab: `CI_PIPELINE_SOURCE`), ref, sha, actor, triggering actor, environment, and `pr_head_sha` (when the run plans a pull/merge request, the commit that was planned) |
| `pull_request` | `{number, url, title, author, head_sha, base_ref, merged, merged_by, merge_commit_sha}` |
| `approval` | apply only. `change_authors` (PR author plus everyone who authored/committed its commits on GitHub, or pushed to its source branch on GitLab), `approved_by` (latest review APPROVED), `approved_head`, `environment` and `environment_approved_by` (approvals of that environment only), `independent_approver` (a non-author, non-bot approved the final commit or the deployment), `stale_approval`, raw `reviews` and `environment_reviews`. GitLab approvals are attributed to the merge request head pushed before each approval |
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

`content_sha256` detects changed bytes. It isn't a signature: anyone able to write a record could compute a matching hash, which is why records are write-once, the version count matters, and records can additionally be signed.

## Checking a signature

With `--kms-key-id`, `<id>.sig` holds `{algorithm, key_id, record_sha256, signature}`: an ECDSA P-256 signature (DER, base64) by the KMS key `key_id` over the SHA-256 of the record object exactly as stored. Check it with the public key:

```bash
aws s3 cp s3://acme-tf-evidence/tfproof/records/apply/acme/infra/2026/11/22/<id>.sig r.sig
aws kms get-public-key --key-id "$(jq -r .key_id r.sig)" --query PublicKey --output text | base64 -d > pub.der
openssl pkey -pubin -inform DER -in pub.der -out pub.pem
jq -r .signature r.sig | base64 -d > sig.der
openssl dgst -sha256 -verify pub.pem -signature sig.der r.json    # "Verified OK"
```

Confirm `key_id` is the key for that phase (the evidence-bucket module's `plan_signing_key_arn` or `apply_signing_key_arn`). Keep the public keys with your audit evidence: a signature can't be checked once its key is gone.
