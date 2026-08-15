package compliance.ac_1_5_least_privilege_test

import rego.v1
import data.compliance.ac_1_5_least_privilege

noncompliant_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"arn:aws:dynamodb:x\"}]}"}},
}]}

compliant_input := {"resource_changes": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"change": {"after": {"policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"dynamodb:PutItem\"],\"Resource\":\"arn:aws:dynamodb:x\"},{\"Effect\":\"Allow\",\"Action\":[\"s3:PutObject\"],\"Resource\":\"arn:aws:s3:x\"}]}"}},
}]}

test_noncompliant_fails if {
	some msg in ac_1_5_least_privilege.deny with input as noncompliant_input
	contains(msg, "AC.L2-3.1.5")
}

test_compliant_passes if {
	count(ac_1_5_least_privilege.deny) == 0 with input as compliant_input
}
