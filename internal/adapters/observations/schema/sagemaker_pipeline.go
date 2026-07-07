package schema

import "github.com/sufield/stave/internal/core/kernel"

var sagemakerPipelineSchema = Schema{
	AssetType: kernel.AssetType("aws_sagemaker_pipeline"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every sagemaker-pipeline control gates on this"},
		{Path: "properties.compute.identity.execution_role.is_overprivileged", Required: true,
			Doc: "overprivileged execution role detection — least-privilege family"},
		{Path: "properties.compute.encryption.uses_customer_kms", Required: false,
			Doc: "CMK encryption for pipeline artifacts; not all collectors populate this yet"},
	},
}

func init() { Register(sagemakerPipelineSchema) }
