package schema

import "github.com/sufield/stave/internal/core/kernel"

var codepipelinePipelineSchema = Schema{
	AssetType: kernel.AssetType("aws_codepipeline_pipeline"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every codepipeline control gates on this"},
		{Path: "properties.compute.identity.execution_role.is_overprivileged", Required: true,
			Doc: "overprivileged pipeline role detection — least-privilege family"},
		{Path: "properties.compute.encryption.artifact_store_encrypted", Required: false,
			Doc: "artifact store KMS encryption; not all collectors populate this yet"},
		{Path: "properties.compute.governance.has_manual_approval", Required: false,
			Doc: "manual approval gate presence; sparse signal from pipeline definition parsing"},
		{Path: "properties.compute.governance.pipeline_type", Required: false,
			Doc: "V1 vs V2 pipeline type; low-severity deprecation signal"},
	},
}

func init() { Register(codepipelinePipelineSchema) }
