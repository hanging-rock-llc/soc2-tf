locals {
  create_kms_key = var.kms_key_arn == null
  kms_key_arn    = local.create_kms_key ? aws_kms_key.evidence[0].arn : var.kms_key_arn
  bucket_arn     = aws_s3_bucket.evidence.arn
  lifecycle_on   = var.glacier_transition_days != null || var.expire_after_days != null
  # ARN prefix for everything tfproof writes, e.g. arn:aws:s3:::bucket/tfproof/
  evidence_arn = var.evidence_prefix == "" ? "${local.bucket_arn}/" : "${local.bucket_arn}/${var.evidence_prefix}/"
}

resource "aws_kms_key" "evidence" {
  count = local.create_kms_key ? 1 : 0

  description             = "tfproof evidence bucket ${var.bucket_name}"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = var.tags
}

resource "aws_kms_alias" "evidence" {
  count = local.create_kms_key ? 1 : 0

  name          = "alias/${var.bucket_name}"
  target_key_id = aws_kms_key.evidence[0].key_id
}

# Record signing keys: one per phase, so a valid signature also shows which
# role wrote the record (only the plan role can use the plan key, only the
# apply role the apply key). Keep these keys, or at least their public keys,
# for as long as the records: signatures can't be checked without them.
resource "aws_kms_key" "signing" {
  for_each = var.create_signing_keys ? toset(["plan", "apply"]) : toset([])

  description              = "tfproof ${each.key} record signing (${var.bucket_name})"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
  tags                     = var.tags
}

resource "aws_kms_alias" "signing" {
  for_each = aws_kms_key.signing

  name          = "alias/${var.bucket_name}-${each.key}-signing"
  target_key_id = each.value.key_id
}

resource "aws_s3_bucket" "evidence" {
  bucket              = var.bucket_name
  object_lock_enabled = true
  force_destroy       = false
  tags                = var.tags
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = var.retention_mode
      days = var.retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  count  = local.lifecycle_on ? 1 : 0
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "tfproof-evidence"
    status = "Enabled"

    filter {}

    dynamic "transition" {
      for_each = var.glacier_transition_days == null ? [] : [var.glacier_transition_days]
      content {
        days          = transition.value
        storage_class = "GLACIER_IR"
      }
    }

    dynamic "noncurrent_version_transition" {
      for_each = var.glacier_transition_days == null ? [] : [var.glacier_transition_days]
      content {
        noncurrent_days = noncurrent_version_transition.value
        storage_class   = "GLACIER_IR"
      }
    }

    dynamic "expiration" {
      for_each = var.expire_after_days == null ? [] : [var.expire_after_days]
      content {
        days = expiration.value
      }
    }

    dynamic "noncurrent_version_expiration" {
      for_each = var.expire_after_days == null ? [] : [var.expire_after_days]
      content {
        noncurrent_days = noncurrent_version_expiration.value
      }
    }
  }

  lifecycle {
    precondition {
      condition     = var.expire_after_days == null || var.expire_after_days > var.retention_days
      error_message = "expire_after_days must be greater than retention_days, or records would expire while still under retention."
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

data "aws_iam_policy_document" "bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Only the CI roles may write evidence. Humans, including admins, can read
  # but not add records, so the store can't be padded after the fact.
  dynamic "statement" {
    for_each = length(var.writer_principal_arns) > 0 ? [1] : []
    content {
      sid       = "OnlyWritersMayPut"
      effect    = "Deny"
      actions   = ["s3:PutObject"]
      resources = ["${local.bucket_arn}/*"]

      principals {
        type        = "*"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnNotLike"
        variable = "aws:PrincipalArn"
        values   = var.writer_principal_arns
      }
    }
  }

  # Records are written once. tfproof creates them with If-None-Match: *, so
  # S3 refuses to put a new version over an existing record; this makes that
  # mandatory for everyone, including the CI roles. (Index objects under
  # index/ are meant to be replaced and are not covered.)
  statement {
    sid       = "RecordsAreWriteOnce"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.evidence_arn}records/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["true"]
    }
  }

  # Evidence is never deleted by hand. Object Lock already blocks deleting
  # locked versions; this also stops anyone (root included) from adding
  # delete markers that would hide records. Changing it requires editing this
  # policy, which CloudTrail records as a management event.
  statement {
    sid    = "DenyEvidenceDeletion"
    effect = "Deny"
    actions = [
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.bucket.json

  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

# Attach to the CI role that runs `terraform plan` (pull requests and main).
# It may write plan records and the indexes, but not apply records: a pull
# request can change its own workflow file and use this role, so it must not
# be able to forge evidence of an apply.
data "aws_iam_policy_document" "plan_writer" {
  statement {
    sid       = "WritePlanEvidence"
    actions   = ["s3:PutObject", "s3:PutObjectRetention"]
    resources = ["${local.evidence_arn}records/plan/*", "${local.evidence_arn}index/*"]
  }

  statement {
    sid       = "ReadEvidence"
    actions   = ["s3:GetObject"]
    resources = ["${local.evidence_arn}*"]
  }

  # Without ListBucket, S3 answers 403 instead of 404 for a missing key, and
  # tfproof can't tell "no plan captured yet" from "access denied".
  statement {
    sid       = "ListEvidence"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]
  }

  statement {
    sid       = "UseEvidenceKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [local.kms_key_arn]
  }

  dynamic "statement" {
    for_each = var.create_signing_keys ? [aws_kms_key.signing["plan"].arn] : []
    content {
      sid       = "SignPlanRecords"
      actions   = ["kms:Sign"]
      resources = [statement.value]
    }
  }
}

# Attach to the CI role that runs `terraform apply` (ideally only assumable
# from the protected deployment environment). It writes apply records and
# reads the indexes to verify the plan.
data "aws_iam_policy_document" "apply_writer" {
  statement {
    sid       = "WriteApplyEvidence"
    actions   = ["s3:PutObject", "s3:PutObjectRetention"]
    resources = ["${local.evidence_arn}records/apply/*"]
  }

  statement {
    sid       = "ReadEvidence"
    actions   = ["s3:GetObject"]
    resources = ["${local.evidence_arn}*"]
  }

  statement {
    sid       = "ListEvidence"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]
  }

  statement {
    sid       = "UseEvidenceKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [local.kms_key_arn]
  }

  dynamic "statement" {
    for_each = var.create_signing_keys ? [aws_kms_key.signing["apply"].arn] : []
    content {
      sid       = "SignApplyRecords"
      actions   = ["kms:Sign"]
      resources = [statement.value]
    }
  }
}

# Attach to the report job role and auditor roles.
data "aws_iam_policy_document" "reader" {
  statement {
    sid       = "ListEvidence"
    actions   = ["s3:ListBucket", "s3:ListBucketVersions"]
    resources = [local.bucket_arn]
  }

  statement {
    sid       = "ReadEvidence"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"]
    resources = ["${local.bucket_arn}/*"]
  }

  statement {
    sid       = "DecryptEvidence"
    actions   = ["kms:Decrypt"]
    resources = [local.kms_key_arn]
  }

  dynamic "statement" {
    for_each = var.create_signing_keys ? [[for k in aws_kms_key.signing : k.arn]] : []
    content {
      sid       = "VerifySignatures"
      actions   = ["kms:GetPublicKey"]
      resources = statement.value
    }
  }
}
