# METADATA
# title: SC.L2-3.13.1 - Lambda VPC Boundary Placement (GAP-05)
# description: "aws_lambda_function.intake must have a non-empty vpc_config block placing it inside the private subnets, not the default Lambda network."
# custom:
#   control_id: SC.L2-3.13.1
#   framework: cmmc
#   severity: high
#   remediation: "Add a vpc_config { subnet_ids = ...; security_group_ids = ... } block to aws_lambda_function.intake (via an override file, since this is an attribute of an existing resource)."
package compliance.sc_13_1_vpc_boundary

import rego.v1

deny contains msg if {
	not has_vpc_config
	msg := "[SC.L2-3.13.1] aws_lambda_function.intake: no vpc_config block found. Remediation: place the function in the private subnets with a hardened security group."
}

has_vpc_config if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	r.name == "intake"
	count(r.expressions.vpc_config) > 0
}
