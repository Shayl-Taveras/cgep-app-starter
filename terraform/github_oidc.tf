# github_oidc.tf
# GitHub Actions CI role for the grc-gate pipeline (Layer 3). Reuses the
# OIDC provider already registered in this account for a different repo —
# AWS allows only one provider per issuer URL per account, so this is a
# new role trusted by the existing provider, not a new provider.
#
# Scope: broad at the service level (this stack spans 8 AWS services), but
# resource-name-prefix-scoped everywhere AWS's IAM condition/resource
# syntax supports it. This is a documented trade-off, not an oversight —
# see WRITEUP.md's trade-offs section: a fully resource-ARN-scoped policy
# (naming every VPC endpoint, every Lambda alias, etc.) is more precise
# but was traded for shipping a working end-to-end pipeline in the
# capstone's timeframe.

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_role" "grc_gate_ci" {
  name = "${local.name_prefix}-grc-gate-ci"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        # GitHub's OIDC "sub" claim now embeds immutable owner/repo IDs
        # (e.g. "repo:OWNER@<org-id>/REPO@<repo-id>:pull_request") instead
        # of the classic "repo:OWNER/REPO:*" form. Match both so the trust
        # policy keeps working regardless of which format GitHub issues.
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:Shayl-Taveras/cgep-app-starter:*",
            "repo:Shayl-Taveras@*/cgep-app-starter@*:*",
          ]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "grc_gate_ci" {
  name = "grc-gate-ci-policy"
  role = aws_iam_role.grc_gate_ci.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadEverythingForPlan"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "lambda:Get*",
          "lambda:List*",
          "apigateway:GET",
          "dynamodb:Describe*",
          "dynamodb:List*",
          "s3:Get*",
          "s3:List*",
          "kms:Describe*",
          "kms:List*",
          "kms:GetKeyPolicy",
          "iam:Get*",
          "iam:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:List*",
          "logs:Describe*",
          "sts:GetCallerIdentity",
        ]
        Resource = "*"
      },
      {
        Sid    = "ManageWorkloadResources"
        Effect = "Allow"
        Action = [
          "ec2:CreateTags", "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet", "ec2:DeleteSubnet",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable", "ec2:CreateRoute", "ec2:DeleteRoute",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway", "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints", "ec2:ModifyVpcEndpoint",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
          "lambda:CreateFunction", "lambda:DeleteFunction", "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration", "lambda:AddPermission", "lambda:RemovePermission",
          "lambda:TagResource", "lambda:UntagResource",
          "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE",
          "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable",
          "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:PutItem",
          "cloudtrail:CreateTrail", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail",
          "cloudtrail:StartLogging", "cloudtrail:StopLogging", "cloudtrail:AddTags",
        ]
        Resource = "*"
      },
      {
        Sid      = "ManageProjectS3Buckets"
        Effect   = "Allow"
        Action   = ["s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucket*", "s3:PutObject", "s3:PutObjectAcl", "s3:DeleteObject"]
        Resource = ["arn:aws:s3:::${local.name_prefix}-*", "arn:aws:s3:::${local.name_prefix}-*/*"]
      },
      {
        Sid      = "ManageProjectIamRolesAndPolicies"
        Effect   = "Allow"
        Action   = ["iam:CreateRole", "iam:DeleteRole", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:TagRole"]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"
      },
      {
        Sid      = "PassLambdaExecutionRole"
        Effect   = "Allow"
        Action   = "iam:PassRole"
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${local.name_prefix}-*"
        Condition = {
          StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" }
        }
      },
      {
        Sid      = "UseCapstoneCmk"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt", "kms:DescribeKey"]
        Resource = aws_kms_key.capstone.arn
      },
      {
        Sid      = "LogsForLambda"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DeleteLogGroup", "logs:TagResource"]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.name_prefix}-*"
      },
    ]
  })
}

output "grc_gate_ci_role_arn" {
  value = aws_iam_role.grc_gate_ci.arn
}
