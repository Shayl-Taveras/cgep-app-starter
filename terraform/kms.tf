# kms.tf
# CMK for the capstone GRC baseline. Rotation enabled. Reused by the S3
# uploads bucket (GAP-01), the DynamoDB submissions table (GAP-02), and the
# evidence vault. CloudTrail's log bucket stays on AES256 — see
# specs/2026-08-14-capstone-design.md, "Networking addendum", for why.
# CMMC: SC.L2-3.13.11 (cryptographic protection of CUI/PHI at rest)

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "capstone" {
  description             = "${local.name_prefix} CMK — S3 uploads, DynamoDB, evidence vault"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowLambdaRuntimeRoleUsage"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lambda.arn }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = "*"
      },
    ]
  })
}

resource "aws_kms_alias" "capstone" {
  name          = "alias/${local.name_prefix}-cmk"
  target_key_id = aws_kms_key.capstone.key_id
}

output "kms_key_arn" {
  value = aws_kms_key.capstone.arn
}
