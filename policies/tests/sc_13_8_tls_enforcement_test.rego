package compliance.sc_13_8_tls_enforcement_test

import rego.v1
import data.compliance.sc_13_8_tls_enforcement

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_s3_bucket_policy.uploads_tls_only",
	"type": "aws_s3_bucket_policy",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
}]}}}

noncompliant_input := {"configuration": {"root_module": {"resources": []}}}

test_compliant_passes if {
	count(sc_13_8_tls_enforcement.deny) == 0 with input as compliant_input
}

test_noncompliant_fails if {
	some msg in sc_13_8_tls_enforcement.deny with input as noncompliant_input
	contains(msg, "SC.L2-3.13.8")
}
