# METADATA
# title: SC.L2-3.13.8 - S3 Uploads Bucket TLS-Only Enforcement (GAP-03)
# description: "aws_s3_bucket.uploads must have a matching aws_s3_bucket_policy denying non-TLS requests."
# custom:
#   control_id: SC.L2-3.13.8
#   framework: cmmc
#   severity: high
#   remediation: "Add an aws_s3_bucket_policy referencing aws_s3_bucket.uploads with a Deny statement conditioned on aws:SecureTransport = false."
package compliance.sc_13_8_tls_enforcement

import rego.v1

target_bucket := "aws_s3_bucket.uploads"

deny contains msg if {
	not has_bucket_policy
	msg := sprintf(
		"[SC.L2-3.13.8] %s: no aws_s3_bucket_policy found. Remediation: add one denying requests where aws:SecureTransport is false.",
		[target_bucket],
	)
}

has_bucket_policy if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref)
}

references_bucket(ref) if ref == target_bucket
references_bucket(ref) if ref == sprintf("%s.id", [target_bucket])
references_bucket(ref) if ref == sprintf("%s.bucket", [target_bucket])
