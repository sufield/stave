package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_kms_key — 41 controls.
var kmsSchema = Schema{
	AssetType: kernel.AssetType("aws_kms_key"),
	Fields: []FieldRequirement{
		{Path: "properties.cryptography.kind", Required: true,
			Doc: "type discriminator; every KMS control gates on this"},
		{Path: "properties.cryptography.policy.has_wildcard_principal", Required: true,
			Doc: "core public-key-policy detection"},
		{Path: "properties.cryptography.lifecycle.pending_deletion", Required: false,
			Doc: "deletion-pending signal; sparse for active keys"},
		{Path: "properties.cryptography.multi_region.is_multi_region", Required: false,
			Doc: "multi-region replica signal; sparse for single-region keys"},
		{Path: "properties.cryptography.dependent_resource_count", Required: false,
			Doc: "fan-out impact heuristic"},
		{Path: "properties.cryptography.key_concentration.resource_count", Required: false,
			Doc: "key-concentration heuristic for blast-radius"},
	},
}

func init() { Register(kmsSchema) }
