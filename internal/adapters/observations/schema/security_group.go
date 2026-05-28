package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_ec2_security_group — 19 controls. Mixed property roots:
// network.kind for most, compute.kind for a few — both flow into
// the controls so Required on both.
var securityGroupSchema = Schema{
	AssetType: kernel.AssetType("aws_ec2_security_group"),
	Fields: []FieldRequirement{
		{Path: "properties.network.kind", Required: true,
			Doc: "primary type discriminator; 16+ controls gate on this"},
		{Path: "properties.compute.kind", Required: false,
			Doc: "secondary discriminator used by 3 compute-classification controls"},
		{Path: "properties.network.security_group.high_risk_ports_exposed", Required: false,
			Doc: "exposure-ports audit; sparse for restrictive SGs"},
		{Path: "properties.network.security_group.icmp_all_types_from_internet", Required: false,
			Doc: "ICMP-exposure audit"},
		{Path: "properties.network.security_group.is_default", Required: false,
			Doc: "default-SG-usage audit"},
		{Path: "properties.network.security_group.is_unused", Required: false,
			Doc: "unused-SG hygiene check"},
	},
}

func init() { Register(securityGroupSchema) }
