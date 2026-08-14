# kms.tf
# CMK for the capstone GRC baseline. Rotation enabled. Reused by the S3
# uploads bucket (GAP-01), the DynamoDB submissions table (GAP-02), and the
# evidence vault. CloudTrail's log bucket stays on AES256 — its log
# delivery would need its own key-policy grant with a SourceArn condition
# to use a CMK, out of scope for the five gaps this CMK exists to close.
# See WRITEUP.md.
# CMMC: SC.L2-3.13.11 (cryptographic protection of CUI/PHI at rest)

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "capstone" {
  description         = "${local.name_prefix} CMK — S3 uploads, DynamoDB, evidence vault"
  enable_key_rotation = true
  # 30, not the 7-day minimum — this key is the custody root for PHI and
  # evidence; a longer window gives more room to notice and reverse an
  # accidental deletion before it's unrecoverable.
  deletion_window_in_days = 30

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
