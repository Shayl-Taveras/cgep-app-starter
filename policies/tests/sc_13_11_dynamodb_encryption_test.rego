package compliance.sc_13_11_dynamodb_encryption_test

import rego.v1
import data.compliance.sc_13_11_dynamodb_encryption

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"server_side_encryption": [{"enabled": {"constant_value": true}}]},
}]}}}

noncompliant_input_disabled := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"server_side_encryption": [{"enabled": {"constant_value": false}}]},
}]}}}

noncompliant_input_missing := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {},
}]}}}

test_compliant_passes if {
	count(sc_13_11_dynamodb_encryption.deny) == 0 with input as compliant_input
}

test_noncompliant_disabled_fails if {
	some msg in sc_13_11_dynamodb_encryption.deny with input as noncompliant_input_disabled
	contains(msg, "SC.L2-3.13.11")
}

test_noncompliant_missing_fails if {
	some msg in sc_13_11_dynamodb_encryption.deny with input as noncompliant_input_missing
	contains(msg, "SC.L2-3.13.11")
}
