package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_iam_role — 27 controls.
var iamRoleSchema = Schema{
	AssetType: kernel.AssetType("aws_iam_role"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every IAM-role control gates on this"},
		{Path: "properties.identity.trust_policy.has_cross_account_trust", Required: true,
			Doc: "cross-account-trust detection — load-bearing for confused-deputy controls"},
		{Path: "properties.identity.policies.service_wildcards_granted", Required: true,
			Doc: "service-wildcard privilege detection"},
		{Path: "properties.identity.vendor_trust.is_external_vendor", Required: false,
			Doc: "vendor-trust classification; sparse for internal roles"},
		{Path: "properties.identity.access_advisor.available", Required: false,
			Doc: "access-advisor data availability signal"},
		{Path: "properties.identity.tags.role-type", Required: false,
			Doc: "role-type tag; sparse when not tagged"},
	},
}

func init() { Register(iamRoleSchema) }
