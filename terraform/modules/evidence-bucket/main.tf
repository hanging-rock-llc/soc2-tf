locals {
  create_kms_key = var.kms_key_arn == null
  kms_key_arn    = local.create_kms_key ? aws_kms_key.evidence[0].arn : var.kms_key_arn
  bucket_arn     = aws_s3_bucket.evidence.arn
  lifecycle_on   = var.glacier_transition_days != null || var.expire_after_days != null
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

# Attach to your CI plan and apply roles.
data "aws_iam_policy_document" "writer" {
  statement {
    sid = "WriteEvidence"
    actions = [
      "s3:PutObject",
      "s3:PutObjectRetention",
      "s3:GetObject",
    ]
    resources = ["${local.bucket_arn}/*"]
  }

  statement {
    sid       = "UseEvidenceKey"
    actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
    resources = [local.kms_key_arn]
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
}
