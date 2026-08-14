# lambda_security_group.tf
# GAP-05: security group for the Lambda's VPC placement (see
# main_override.tf, which merges the vpc_config referencing this SG into
# aws_lambda_function.intake). Split into its own file, rather than
# main_override.tf, because Terraform's override-file mechanism only
# permits merging into resources that already exist in a primary config
# file — a wholly new resource address inside an *_override.tf file fails
# `terraform validate`.
# CMMC: SC.L2-3.13.1 (boundary protection — egress restricted to the S3
# and DynamoDB gateway endpoints only)

resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-sg-${local.suffix}"
  description = "Lambda egress restricted to S3 and DynamoDB gateway endpoints"
  vpc_id      = aws_vpc.main.id

  egress {
    description     = "HTTPS to S3 and DynamoDB via VPC gateway endpoints only"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [aws_vpc_endpoint.s3.prefix_list_id, aws_vpc_endpoint.dynamodb.prefix_list_id]
  }

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# GAP-05 fix: a Lambda function with vpc_config requires its execution
# role to call ec2:CreateNetworkInterface / DescribeNetworkInterfaces /
# DeleteNetworkInterface so AWS can attach ENIs in the private subnets.
# The starter's AWSLambdaBasicExecutionRole (main.tf) only grants
# CloudWatch Logs permissions, not EC2 ENI permissions — apply fails with
# "InvalidParameterValueException: The provided execution role does not
# have permissions to call CreateNetworkInterface on EC2" without this.
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
