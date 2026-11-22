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
  value       = "s3://${aws_s3_bucket.evidence.id}/tfproof"
}

output "writer_policy_json" {
  description = "IAM policy to attach to CI plan/apply roles so tfproof can write records."
  value       = data.aws_iam_policy_document.writer.json
}

output "reader_policy_json" {
  description = "IAM policy for the report job and auditors."
  value       = data.aws_iam_policy_document.reader.json
}
