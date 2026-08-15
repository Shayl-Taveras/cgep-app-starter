package compliance.mp_3_8_9_versioning_test

import rego.v1
import data.compliance.mp_3_8_9_versioning

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_s3_bucket_versioning.uploads",
	"type": "aws_s3_bucket_versioning",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
		"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
	},
}]}}}

noncompliant_input_suspended := {"configuration": {"root_module": {"resources": [{
	"address": "aws_s3_bucket_versioning.uploads",
	"type": "aws_s3_bucket_versioning",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
		"versioning_configuration": [{"status": {"constant_value": "Suspended"}}],
	},
}]}}}

noncompliant_input_missing := {"configuration": {"root_module": {"resources": []}}}

test_compliant_passes if {
	count(mp_3_8_9_versioning.deny) == 0 with input as compliant_input
}

test_noncompliant_suspended_fails if {
	some msg in mp_3_8_9_versioning.deny with input as noncompliant_input_suspended
	contains(msg, "MP.L2-3.8.9")
}

test_noncompliant_missing_fails if {
	some msg in mp_3_8_9_versioning.deny with input as noncompliant_input_missing
	contains(msg, "MP.L2-3.8.9")
}
