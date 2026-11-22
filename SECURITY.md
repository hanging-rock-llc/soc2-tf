# Security

tfproof produces audit evidence, so its own integrity matters.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on this repository's Security tab rather than opening a public issue. We aim to acknowledge reports within three business days.

## Design choices that limit risk

- **No third-party dependencies.** The binary is built from the Go standard library and this repository only, including its AWS SigV4 signer (tested against AWS's published test vectors). There's no transitive supply chain to audit.
- **No state access, no cloud credentials beyond the evidence bucket.** tfproof never reads Terraform state and never needs permissions on the infrastructure Terraform manages. It needs `s3:PutObject`, `s3:GetObject` and `s3:ListBucket` on the evidence bucket, and `kms:Sign` on its signing key if you sign records (`sts:GetCallerIdentity` requires no permission). The evidence-bucket module's `plan_writer_policy_json` and `apply_writer_policy_json` split write and signing access by phase, so the plan role (reachable from any pull request) can't write or sign apply records.
- **Write-once, signed records.** Records are created with `If-None-Match: *`, the bucket policy rejects record writes without it, and `tfproof report` flags any record with more than one version. With `kms-key-id`, each record is signed by its phase's KMS key and `report` checks the signatures. Anyone who can assume the apply role can still write and sign apply records, so restrict its OIDC trust to `repo:<owner>/<repo>:environment:production` (GitLab: a protected environment), with that environment's deployment branches limited to `main` (available on GitHub Pro and Team; required reviewers aren't needed for this).
- **No server.** Evidence goes straight from your CI runner to your bucket.
- **No shell interpolation of inputs.** The GitHub Action passes every input to the binary as an environment variable, and warnings printed as workflow annotations are escaped.
- **Apply logs are hashed, not stored, by default.** Terraform output can include sensitive values; logs are only uploaded with `upload-log: true`.

## Pinning

Pin the action to a full commit SHA (`uses: hanging-rock-llc/soc2-tf@<sha>`) in production workflows, as you would any action that runs in a job holding cloud credentials. If that SHA is a release tag's commit, the action runs the release binary only after checking its SHA-256 against the release's `checksums.txt` and its build provenance with `gh attestation verify --signer-workflow hanging-rock-llc/soc2-tf/.github/workflows/release.yml`; otherwise it builds from the pinned source.
