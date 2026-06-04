package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eventbridge_rule — 16 controls. governance.kind is the type
// discriminator; pattern/filter and delivery signals (has_overlapping_pattern,
// subscribes_sensitive_source, has_narrowing_filter, has_dlq, has_retries)
// drive the pattern-overlap, sensitive-source, and delivery-resilience families.
var eventbridgeRuleSchema = Schema{
	AssetType: kernel.AssetType("aws_eventbridge_rule"),
	Fields: []FieldRequirement{
		{Path: "properties.governance.kind", Required: true,
			Doc: "type discriminator; every EventBridge-rule control gates on this"},
		{Path: "properties.governance.events.has_overlapping_pattern", Required: true,
			Doc: "pattern-overlap detection signal for the rule-pattern family"},
		{Path: "properties.governance.events.subscribes_sensitive_source", Required: true,
			Doc: "sensitive-source subscription signal — foundational for filter-scope controls"},
		{Path: "properties.governance.events.has_narrowing_filter", Required: true,
			Doc: "narrowing-filter presence; pairs with sensitive-source detection"},
		{Path: "properties.governance.events.has_dlq", Required: true,
			Doc: "dead-letter-queue presence — core delivery-resilience signal"},
		{Path: "properties.governance.events.has_retries", Required: true,
			Doc: "retry-policy presence — core delivery-resilience signal"},
		{Path: "properties.governance.events.has_ghost_dlq", Required: false,
			Doc: "ghost-DLQ signal; sparse, only when a DLQ ref is dangling"},
		{Path: "properties.governance.events.has_self_publishing_loop", Required: false,
			Doc: "self-publishing-loop signal; sparse feedback-loop detection"},
		{Path: "properties.governance.events.alarm_failed_invocations_configured", Required: false,
			Doc: "failed-invocation alarm coverage; sparse when no alarm wired"},
	},
}

func init() { Register(eventbridgeRuleSchema) }
