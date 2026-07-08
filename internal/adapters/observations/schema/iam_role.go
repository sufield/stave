package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_iam_role — 27 controls.
var iamRoleSchema = Schema{
	AssetType: kernel.AssetType("aws_iam_role"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every IAM-role control gates on this"},
		{Path: "properties.identity.trust_policy.has_cross_account_trust", Required: true,
			Doc: "cross-account-trust detection — foundational for confused-deputy controls"},
		{Path: "properties.identity.policies.service_wildcards_granted", Required: true,
			Doc: "service-wildcard privilege detection"},
		{Path: "properties.identity.vendor_trust.is_external_vendor", Required: false,
			Doc: "vendor-trust classification; sparse for internal roles"},
		{Path: "properties.identity.access_advisor.available", Required: false,
			Doc: "access-advisor data availability signal"},
		{Path: "properties.identity.tags.role-type", Required: false,
			Doc: "role-type tag; sparse when not tagged"},
		{Path: "properties.identity.policies.has_wildcard_s3_resource", Required: false,
			Doc: "s3 actions on Resource:*; sparse when role has no S3 grants"},
		{Path: "properties.identity.policies.passrole_targets_production", Required: false,
			Doc: "PassRole targets a production role ARN; sparse when no PassRole"},
		{Path: "properties.identity.policies.has_cross_account_resource", Required: false,
			Doc: "any Resource ARN with a different account ID; sparse for same-account roles"},
	},
}

func init() { Register(iamRoleSchema) }
