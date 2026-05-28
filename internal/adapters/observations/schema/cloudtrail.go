package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_cloudtrail_trail — 44 controls. Two parallel root paths
// (audit.* for older controls, audit_trail.* for newer ones); both
// .kind discriminators flow into the corresponding control subsets,
// so Required on both reflects the actual catalog usage.
var cloudtrailSchema = Schema{
	AssetType: kernel.AssetType("aws_cloudtrail_trail"),
	Fields: []FieldRequirement{
		{Path: "properties.audit.kind", Required: true,
			Doc: "legacy type discriminator; 30+ controls gate on this"},
		{Path: "properties.audit_trail.kind", Required: true,
			Doc: "current type discriminator; the audit_trail.* control family"},
		{Path: "properties.audit_trail.multi_region_enabled", Required: false,
			Doc: "regional-coverage signal for multi-region trails"},
		{Path: "properties.audit_trail.s3_data_events.read_enabled", Required: false,
			Doc: "data-events coverage signal; sparse without data events"},
		{Path: "properties.audit_trail.s3_data_events.write_enabled", Required: false,
			Doc: "data-events coverage signal; sparse without data events"},
		{Path: "properties.audit.cloudtrail.cw_logs_delivery_configured", Required: false,
			Doc: "CloudWatch Logs delivery signal"},
	},
}

func init() { Register(cloudtrailSchema) }
