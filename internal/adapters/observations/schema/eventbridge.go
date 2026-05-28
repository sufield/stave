package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eventbridge_bus — 18 controls.
var eventbridgeBusSchema = Schema{
	AssetType: kernel.AssetType("aws_eventbridge_bus"),
	Fields: []FieldRequirement{
		{Path: "properties.governance.kind", Required: true,
			Doc: "type discriminator; every EventBridge-bus control gates on this"},
		{Path: "properties.governance.events.rule_count", Required: false,
			Doc: "rule-fanout audit signal"},
		{Path: "properties.governance.events.policy_statement_count", Required: false,
			Doc: "policy-shape audit signal"},
		{Path: "properties.governance.events.policy_s3_has_source", Required: false,
			Doc: "S3-source constraint signal; sparse when no S3 policy"},
	},
}

func init() { Register(eventbridgeBusSchema) }
