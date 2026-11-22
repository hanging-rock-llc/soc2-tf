# Record schema (`tfproof.dev/record/v1`)

Each plan or apply produces one JSON record.

## Object layout

Relative to the sink prefix (e.g. `s3://acme-tf-evidence/tfproof/`):

```
records/<owner>/<repo>/<yyyy>/<mm>/<dd>/<run_id>-<attempt>-<job>-<phase>-<workdir>.json   immutable records
records/.../<same>.log                                                                apply log (only with --upload-log)
index/<owner>/<repo>/run/<run_id>/<workdir>/plan.json                                 latest plan in a run
index/<owner>/<repo>/pr/<number>/<workdir>/plan.json                                  latest plan on a PR
```

Index objects are overwritten as new plans arrive. On a versioned Object Lock bucket every prior version is retained, so the history stays intact.

## Fields

| Field | Description |
|---|---|
| `schema` | `tfproof.dev/record/v1` |
| `id` | `<run_id>-<attempt>-<job>-<phase>-<workdir>` |
| `phase` | `plan` or `apply` |
| `captured_at` | UTC timestamp |
| `tool` | `{name, version}` |
| `iac` | `{binary, version, workdir}` |
| `run` | GitHub Actions context: repository, workflow, job, run ID/attempt/URL, event, ref, sha, actor, triggering actor, environment |
| `pull_request` | `{number, url, title, author, head_sha, base_ref, merged, merged_by, merge_commit_sha}` |
| `approval` | apply only. `approved_by` (latest review APPROVED), `approved_head`, `environment_approved_by`, `independent_approver`, raw `reviews` and `environment_reviews` |
| `cloud_identity` | `{account, arn, role_name, role_session_name}` from `sts:GetCallerIdentity` |
| `plan` | `file_sha256` (binary plan), `json_sha256`, `terraform_version`, `summary` (create/update/delete/replace/read/forget/import/no_op counts), `has_changes`, `changes[]` (`address`, `kind`, `action`, `actions`), `changeset_digest` |
| `apply` | `exit_code`, `succeeded`, `log_sha256`, `log_key`, `verification` |
| `apply.verification` | `checked`, `same_run_match`, `same_run_record`, `pull_request_match`, `pull_request_record`, `passed`, `notes[]` |
| `warnings` | anything tfproof couldn't collect (e.g. missing token permissions) |
| `content_sha256` | SHA-256 of the compact JSON encoding of the record with this field set to `""` |

## Change-set digest

`changeset_digest` is the SHA-256 of the sorted lines `<kind>|<address>|<action>` for every change except no-ops and data-source reads. Two plans that would make the same changes produce the same digest, which is how an apply-on-merge plan is matched to the plan reviewed on the pull request even though the binary plan files differ.

The digest covers *which* resources change and *how* (create, update, replace, delete), not attribute values. The same-run check (`same_run_match`) compares the exact binary plan file, which does cover values.

## Verifying a record by hand

```bash
aws s3 cp s3://acme-tf-evidence/tfproof/records/acme/infra/2026/11/22/<id>.json r.json
want=$(jq -r .content_sha256 r.json)
got=$(jq -cj '.content_sha256 = ""' r.json | sha256sum | cut -d' ' -f1)
[ "$want" = "$got" ] && echo intact || echo ALTERED
```

`jq -c` key order matches Go's encoding (struct field order), so this works as long as jq doesn't reorder keys (don't pass `-S`).
