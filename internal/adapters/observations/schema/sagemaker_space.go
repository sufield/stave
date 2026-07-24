package schema

import "github.com/sufield/stave/internal/core/kernel"

var sagemakerSpaceSchema = Schema{
	AssetType: kernel.AssetType("aws_sagemaker_space"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every sagemaker-space control gates on this"},
		{Path: "properties.compute.sharing.type", Required: true,
			Doc: "sharing type (Private/Shared) — user isolation family"},
	},
}

func init() { Register(sagemakerSpaceSchema) }
