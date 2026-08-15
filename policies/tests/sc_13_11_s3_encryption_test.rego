package compliance.sc_13_11_s3_encryption_test

import rego.v1
import data.compliance.sc_13_11_s3_encryption

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
		"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "aws:kms"}}]}],
	},
}]}}}

noncompliant_input_wrong_algo := {"configuration": {"root_module": {"resources": [{
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
		"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": {"constant_value": "AES256"}}]}],
	},
}]}}}

noncompliant_input_missing := {"configuration": {"root_module": {"resources": []}}}

test_compliant_passes if {
	count(sc_13_11_s3_encryption.deny) == 0 with input as compliant_input
}

test_noncompliant_wrong_algo_fails if {
	some msg in sc_13_11_s3_encryption.deny with input as noncompliant_input_wrong_algo
	contains(msg, "SC.L2-3.13.11")
}

test_noncompliant_missing_fails if {
	some msg in sc_13_11_s3_encryption.deny with input as noncompliant_input_missing
	contains(msg, "SC.L2-3.13.11")
}
