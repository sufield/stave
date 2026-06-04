package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_eventbridge_schedule — 10 controls. governance.kind is the type
// discriminator; DLQ presence, schedule-expression validity/timezone, and the
// scheduler IAM-trust/wildcard signals drive the scheduler resilience,
// timezone-correctness, and least-privilege families.
var eventbridgeScheduleSchema = Schema{
	AssetType: kernel.AssetType("aws_eventbridge_schedule"),
	Fields: []FieldRequirement{
		{Path: "properties.governance.kind", Required: true,
			Doc: "type discriminator; every EventBridge-schedule control gates on this"},
		{Path: "properties.governance.events.has_dlq", Required: true,
			Doc: "dead-letter-queue presence — core delivery-resilience signal"},
		{Path: "properties.governance.events.schedule_expression_valid", Required: true,
			Doc: "schedule-expression validity — foundational correctness signal"},
		{Path: "properties.governance.events.uses_cron_expression", Required: true,
			Doc: "cron-expression flag; gates timezone-correctness controls"},
		{Path: "properties.governance.events.schedule_expression_timezone", Required: true,
			Doc: "schedule timezone — core timezone-correctness signal"},
		{Path: "properties.governance.events.role_has_wildcard", Required: true,
			Doc: "scheduler-role wildcard detection — least-privilege signal"},
		{Path: "properties.governance.events.role_trust_scheduler_only", Required: false,
			Doc: "scheduler-only trust scoping; sparse trust-policy signal"},
		{Path: "properties.governance.events.has_ghost_dlq", Required: false,
			Doc: "ghost-DLQ signal; sparse, only when a DLQ ref is dangling"},
		{Path: "properties.governance.events.alarm_dropped_configured", Required: false,
			Doc: "dropped-event alarm coverage; sparse when no alarm wired"},
	},
}

func init() { Register(eventbridgeScheduleSchema) }
