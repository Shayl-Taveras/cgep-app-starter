# dynamodb_hardening_override.tf
# Closes GAP-02: the submissions table used the AWS-owned default key.
# server_side_encryption is an attribute of the table resource itself (no
# separate resource type exists for it, unlike S3), so this merges into
# the starter's aws_dynamodb_table.intake via Terraform's override-file
# mechanism — the filename suffix (_override.tf) is what makes this merge
# instead of conflict.
# CMMC: SC.L2-3.13.11

resource "aws_dynamodb_table" "intake" {
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.capstone.arn
  }
}
