package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_vpc — 13 controls. Network-domain type rooted under
// properties.network.*; network.kind is the discriminator and the
// vpc.* booleans drive the default-VPC, segmentation, and IGW families.
var vpcSchema = Schema{
	AssetType: kernel.AssetType("aws_vpc"),
	Fields: []FieldRequirement{
		{Path: "properties.network.kind", Required: true,
			Doc: "type discriminator; every VPC control gates on this"},
		{Path: "properties.network.vpc.is_default", Required: true,
			Doc: "default-VPC detection — foundational for the default-VPC family"},
		{Path: "properties.network.vpc.has_active_resources", Required: true,
			Doc: "active-resource signal; pairs with is_default for default-VPC controls"},
		{Path: "properties.network.vpc.igw_appears_unnecessary", Required: true,
			Doc: "core unnecessary-IGW detection signal"},
		{Path: "properties.network.vpc.has_mixed_environments", Required: false,
			Doc: "environment-segmentation audit; sparse for single-env VPCs"},
		{Path: "properties.network.flow_log.enabled", Required: false,
			Doc: "flow-log audit; feature-gated, populated only when logging is configured"},
		{Path: "properties.network.dns.firewall_enabled", Required: false,
			Doc: "DNS-firewall signal; sparse when Route 53 Resolver firewall is unused"},
		{Path: "properties.network.endpoint.has_all_critical", Required: false,
			Doc: "VPC-endpoint coverage audit; feature-gated on endpoint configuration"},
	},
}

func init() { Register(vpcSchema) }
