package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_sqs_queue — 30 controls.
var sqsSchema = Schema{
	AssetType: kernel.AssetType("aws_sqs_queue"),
	Fields: []FieldRequirement{
		{Path: "properties.messaging.kind", Required: true,
			Doc: "type discriminator; every SQS control gates on this"},
		{Path: "properties.messaging.sqs.is_dlq", Required: true,
			Doc: "DLQ vs primary queue discrimination; drives 7+ controls"},
		{Path: "properties.messaging.sqs.uses_cmk", Required: false,
			Doc: "CMK-vs-AWS-managed encryption signal"},
		{Path: "properties.messaging.sqs.uses_short_polling", Required: false,
			Doc: "polling-mode signal for cost/reliability controls"},
		{Path: "properties.messaging.sqs.visibility_exceeds_retention", Required: false,
			Doc: "timing-mismatch signal"},
	},
}

func init() { Register(sqsSchema) }
