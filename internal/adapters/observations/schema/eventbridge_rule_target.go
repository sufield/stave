package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eventbridge_rule_target — 9 controls. governance.kind is the
// type discriminator; events.target_type + has_ghost_target drive the
// ghost-target and federation-spoke families that gate on a deleted
// target ARN.
var eventbridgeRuleTargetSchema = Schema{
	AssetType: kernel.AssetType("aws_eventbridge_rule_target"),
	Fields: []FieldRequirement{
		{Path: "properties.governance.kind", Required: true,
			Doc: "type discriminator; every rule-target control gates on this"},
		{Path: "properties.governance.events.target_type", Required: true,
			Doc: "target taxonomy; selects which ghost-target control applies"},
		{Path: "properties.governance.events.has_ghost_target", Required: true,
			Doc: "core ghost-target detection signal — deleted target ARN"},
		{Path: "properties.governance.events.has_ghost_invocation_role", Required: false,
			Doc: "ghost invocation-role signal; sparse for role-less targets"},
	},
}

func init() { Register(eventbridgeRuleTargetSchema) }
