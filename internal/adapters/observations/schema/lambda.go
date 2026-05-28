package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_lambda_function — 57 controls.
var lambdaSchema = Schema{
	AssetType: kernel.AssetType("aws_lambda_function"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every lambda control gates on this"},
		{Path: "properties.compute.logging.log_group_exists", Required: true,
			Doc: "log-group presence — load-bearing for the logging audit family"},
		{Path: "properties.compute.async.dlq_configured", Required: false,
			Doc: "async-invocation DLQ; sparse when no async invocation path"},
		{Path: "properties.network.lambda.vpc_configured", Required: false,
			Doc: "VPC attachment signal; sparse for non-VPC lambdas"},
		{Path: "properties.network.lambda.sg_egress_unrestricted", Required: false,
			Doc: "security-group egress audit; sparse without VPC"},
	},
}

func init() { Register(lambdaSchema) }
