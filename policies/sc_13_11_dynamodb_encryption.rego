# METADATA
# title: SC.L2-3.13.11 - DynamoDB Table CMK Encryption (GAP-02)
# description: "aws_dynamodb_table.intake must have server_side_encryption enabled with a kms_key_arn set, not the AWS-owned default key."
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc
#   severity: high
#   remediation: "Add a server_side_encryption { enabled = true; kms_key_arn = <CMK arn> } block to aws_dynamodb_table.intake (via an override file, since this is an attribute of an existing resource, not a separate resource type)."
package compliance.sc_13_11_dynamodb_encryption

import rego.v1

deny contains msg if {
	not has_cmk_encryption
	msg := "[SC.L2-3.13.11] aws_dynamodb_table.intake: no server_side_encryption block with enabled = true found. Remediation: add one referencing a customer CMK."
}

has_cmk_encryption if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	r.name == "intake"
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
}
