# METADATA
# title: AC.L2-3.1.5 - Lambda Least-Privilege IAM (GAP-07)
# description: "aws_iam_role_policy.lambda_inline must not grant any wildcard (service:*) action."
# custom:
#   control_id: AC.L2-3.1.5
#   framework: cmmc
#   severity: high
#   remediation: "Replace any \"service:*\" action in aws_iam_role_policy.lambda_inline with the specific actions the handler needs (e.g. dynamodb:PutItem, s3:PutObject)."
package compliance.ac_1_5_least_privilege

import rego.v1

as_list(x) := x if is_array(x)

as_list(x) := [x] if not is_array(x)

wildcard_actions contains action if {
	some rc in input.resource_changes
	rc.address == "aws_iam_role_policy.lambda_inline"
	rc.change.after.policy != null
	doc := json.unmarshal(rc.change.after.policy)
	some stmt in doc.Statement
	some action in as_list(stmt.Action)
	endswith(action, ":*")
}

deny contains msg if {
	some action in wildcard_actions
	msg := sprintf("[AC.L2-3.1.5] aws_iam_role_policy.lambda_inline grants wildcard action %q. Remediation: scope this to the specific actions the handler needs.", [action])
}
