# METADATA
# title: MP.L2-3.8.9 - S3 Uploads Bucket Versioning (GAP-04)
# description: "aws_s3_bucket.uploads must have a matching aws_s3_bucket_versioning resource with status Enabled."
# custom:
#   control_id: MP.L2-3.8.9
#   framework: cmmc
#   severity: moderate
#   remediation: "Add aws_s3_bucket_versioning referencing aws_s3_bucket.uploads with versioning_configuration { status = \"Enabled\" }."
package compliance.mp_3_8_9_versioning

import rego.v1

target_bucket := "aws_s3_bucket.uploads"

deny contains msg if {
	not has_versioning_enabled
	msg := sprintf(
		"[MP.L2-3.8.9] %s: no aws_s3_bucket_versioning with status Enabled found. Remediation: add one referencing this bucket.",
		[target_bucket],
	)
}

has_versioning_enabled if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref)
	some vc in r.expressions.versioning_configuration
	vc.status.constant_value == "Enabled"
}

references_bucket(ref) if ref == target_bucket
references_bucket(ref) if ref == sprintf("%s.id", [target_bucket])
references_bucket(ref) if ref == sprintf("%s.bucket", [target_bucket])
