package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_iam_user — 29 controls.
var iamUserSchema = Schema{
	AssetType: kernel.AssetType("aws_iam_user"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every IAM-user control gates on this"},
		{Path: "properties.identity.policies.has_admin_access", Required: true,
			Doc: "admin-grant detection — foundational for the privilege controls"},
		{Path: "properties.identity.policies.service_wildcards_granted", Required: true,
			Doc: "service-wildcard privilege detection"},
		{Path: "properties.identity.console_access.mfa_enabled", Required: false,
			Doc: "MFA-coverage audit; sparse when no console access"},
		{Path: "properties.identity.user.sensitive_resource_count", Required: false,
			Doc: "blast-radius heuristic"},
		{Path: "properties.identity.user.reachable_resources_count", Required: false,
			Doc: "reachability-fan-out heuristic"},
	},
}

func init() { Register(iamUserSchema) }
