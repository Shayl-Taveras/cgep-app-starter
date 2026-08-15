# METADATA
# title: SC.L2-3.13.11 - S3 Uploads Bucket CMK Encryption (GAP-01)
# description: "aws_s3_bucket.uploads must have a matching aws_s3_bucket_server_side_encryption_configuration using aws:kms, not SSE-S3."
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration referencing aws_s3_bucket.uploads with sse_algorithm = \"aws:kms\" and kms_master_key_id set to a customer CMK."
package compliance.sc_13_11_s3_encryption

import rego.v1

target_bucket := "aws_s3_bucket.uploads"

deny contains msg if {
	not has_kms_encryption
	msg := sprintf(
		"[SC.L2-3.13.11] %s: no aws_s3_bucket_server_side_encryption_configuration using aws:kms found. Remediation: add one referencing this bucket with sse_algorithm = \"aws:kms\".",
		[target_bucket],
	)
}

has_kms_encryption if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref)
	some rule in r.expressions.rule
	some sse in rule.apply_server_side_encryption_by_default
	sse.sse_algorithm.constant_value == "aws:kms"
}

references_bucket(ref) if ref == target_bucket
references_bucket(ref) if ref == sprintf("%s.id", [target_bucket])
references_bucket(ref) if ref == sprintf("%s.bucket", [target_bucket])
