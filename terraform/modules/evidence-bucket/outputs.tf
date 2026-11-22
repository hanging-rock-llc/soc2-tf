output "bucket_name" {
  description = "Evidence bucket name."
  value       = aws_s3_bucket.evidence.id
}

output "bucket_arn" {
  description = "Evidence bucket ARN."
  value       = aws_s3_bucket.evidence.arn
}

output "kms_key_arn" {
  description = "KMS key encrypting the evidence bucket."
  value       = local.kms_key_arn
}

output "sink_uri" {
  description = "Value for tfproof's --sink / TFPROOF_SINK."
  value       = trimsuffix("s3://${aws_s3_bucket.evidence.id}/${var.evidence_prefix}", "/")
}

output "plan_writer_policy_json" {
  description = "IAM policy for the CI role that runs terraform plan: writes plan records and indexes."
  value       = data.aws_iam_policy_document.plan_writer.json
}

output "apply_writer_policy_json" {
  description = "IAM policy for the CI role that runs terraform apply: writes apply records and reads indexes to verify."
  value       = data.aws_iam_policy_document.apply_writer.json
}

output "plan_signing_key_arn" {
  description = "KMS key that signs plan records (--kms-key-id for capture plan, --plan-signing-key for report). Null when create_signing_keys is false."
  value       = var.create_signing_keys ? aws_kms_key.signing["plan"].arn : null
}

output "apply_signing_key_arn" {
  description = "KMS key that signs apply records (--kms-key-id for capture apply, --apply-signing-key for report). Null when create_signing_keys is false."
  value       = var.create_signing_keys ? aws_kms_key.signing["apply"].arn : null
}

output "reader_policy_json" {
  description = "IAM policy for the report job and auditors."
  value       = data.aws_iam_policy_document.reader.json
}
