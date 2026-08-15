package compliance.sc_13_1_vpc_boundary_test

import rego.v1
import data.compliance.sc_13_1_vpc_boundary

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"vpc_config": [{
		"subnet_ids": {"references": ["aws_subnet.private"]},
		"security_group_ids": {"references": ["aws_security_group.lambda.id"]},
	}]},
}]}}}

noncompliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {},
}]}}}

test_compliant_passes if {
	count(sc_13_1_vpc_boundary.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in sc_13_1_vpc_boundary.deny with input as noncompliant_input
	contains(msg, "SC.L2-3.13.1")
}
