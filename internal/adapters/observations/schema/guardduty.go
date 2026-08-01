package schema

import "github.com/sufield/stave/internal/core/kernel"

var guarddutySchema = Schema{
	AssetType: kernel.AssetType("aws_guardduty_detector"),
	Fields: []FieldRequirement{
		{Path: "properties.threat_detection.kind", Required: true,
			Doc: "type discriminator; every GuardDuty control gates on this (kind=detector)"},
		{Path: "properties.threat_detection.enabled", Required: true,
			Doc: "detector enabled state; foundational signal"},
		// Preview: investigation agent is in public preview as of July 2026.
		// Review field derivation at GA.
		{Path: "properties.threat_detection.investigation.enabled", Required: false,
			Doc: "GuardDuty investigation feature enabled"},
	},
}

func init() { Register(guarddutySchema) }
