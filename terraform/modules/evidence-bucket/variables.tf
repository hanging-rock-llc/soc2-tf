variable "bucket_name" {
  description = "Name of the evidence bucket."
  type        = string
}

variable "retention_days" {
  description = "Default Object Lock retention. SOC 2 Type II covers a 6-12 month window and the audit happens after it ends, so keep at least ~400 days."
  type        = number
  default     = 400

  validation {
    condition     = var.retention_days >= 1
    error_message = "retention_days must be at least 1."
  }
}

variable "retention_mode" {
  description = "COMPLIANCE (no one, including root, can shorten retention or delete) or GOVERNANCE (principals with s3:BypassGovernanceRetention can). Use GOVERNANCE while trialing tfproof, COMPLIANCE for real evidence."
  type        = string
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.retention_mode)
    error_message = "retention_mode must be COMPLIANCE or GOVERNANCE."
  }
}

variable "kms_key_arn" {
  description = "Existing KMS key for bucket encryption. If null, the module creates one."
  type        = string
  default     = null
}

variable "glacier_transition_days" {
  description = "Move records to Glacier Instant Retrieval after this many days (null to disable)."
  type        = number
  default     = 90
}

variable "expire_after_days" {
  description = "Expire record versions after this many days (null keeps them forever). Must be greater than retention_days."
  type        = number
  default     = null
}

variable "writer_principal_arns" {
  description = "IAM role ARNs (your CI plan/apply roles) allowed to write evidence. Used in the bucket policy as the only principals that may PutObject."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default     = {}
}
