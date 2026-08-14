# main_override.tf
# GAP-05: place the Lambda in the starter's private subnets. GAP-07:
# replace the dynamodb:*/s3:* wildcard inline policy with the three
# actions the handler actually calls (terraform/lambda/handler.py:
# dynamodb:PutItem, s3:PutObject, plus the KMS actions the CMK now
# requires). Both aws_lambda_function.intake and
# aws_iam_role_policy.lambda_inline already exist at these addresses in
# main.tf — this file's _override.tf suffix merges these blocks into them
# rather than redeclaring the whole resource.
#
# Note: aws_security_group.lambda (referenced below) is NOT declared in
# this file. Terraform's override-file mechanism requires every block in
# an *_override.tf file to correspond to a resource that already exists
# in a primary config file — a brand-new resource address in an override
# file fails `terraform validate` with "Missing resource to override." It
# lives in lambda_security_group.tf instead, as an ordinary (non-override)
# resource.
# CMMC: SC.L2-3.13.1 (GAP-05), AC.L2-3.1.5 (GAP-07, least privilege)

resource "aws_lambda_function" "intake" {
  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.lambda.id]
  }
}

resource "aws_iam_role_policy" "lambda_inline" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = aws_dynamodb_table.intake.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.uploads.arn}/uploads/*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = aws_kms_key.capstone.arn
      },
    ]
  })
}
