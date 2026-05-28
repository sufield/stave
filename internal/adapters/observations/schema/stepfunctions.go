package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_stepfunctions_state_machine — 111 controls (the largest single
// asset-type control set in the catalog). properties.compute.kind is
// the type-discriminator every state-machine control gates on; an
// extractor that omits it makes the entire stepfunctions control
// family silently no-op.
var stepfunctionsSchema = Schema{
	AssetType: kernel.AssetType("aws_stepfunctions_state_machine"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every stepfunctions control gates on this"},
		{Path: "properties.compute.asl.has_distributed_map", Required: false,
			Doc: "drives the distributed-map control family"},
		{Path: "properties.compute.role.sts_assume_wildcard", Required: false,
			Doc: "trust-policy guard for state-machine roles"},
		{Path: "properties.compute.alarms.executions_failed_alarm", Required: false,
			Doc: "alarm-coverage control family"},
	},
}

func init() { Register(stepfunctionsSchema) }
