package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_sns_topic — 24 controls.
var snsSchema = Schema{
	AssetType: kernel.AssetType("aws_sns_topic"),
	Fields: []FieldRequirement{
		{Path: "properties.messaging.kind", Required: true,
			Doc: "type discriminator; every SNS control gates on this"},
		{Path: "properties.messaging.sns.has_any_delivery_logging", Required: true,
			Doc: "delivery-logging coverage — foundational for the audit family"},
		{Path: "properties.messaging.sns.uses_cmk", Required: false,
			Doc: "CMK-vs-AWS-managed encryption signal"},
		{Path: "properties.messaging.sns.subscribe_broadly_granted", Required: false,
			Doc: "subscribe-permission audit"},
		{Path: "properties.messaging.sns.setattr_broadly_granted", Required: false,
			Doc: "setattr-permission audit"},
	},
}

func init() { Register(snsSchema) }
