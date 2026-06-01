package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_ec2_instance — 37 controls.
var ec2InstanceSchema = Schema{
	AssetType: kernel.AssetType("aws_ec2_instance"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every EC2-instance control gates on this"},
		{Path: "properties.compute.network.imdsv2_required", Required: true,
			Doc: "IMDSv2 enforcement — foundational for the SSRF-defence control"},
		{Path: "properties.compute.network.has_public_ip", Required: true,
			Doc: "public-IP exposure signal"},
		{Path: "properties.compute.instance.sg_allows_ssh", Required: false,
			Doc: "SSH-ingress audit; depends on the attached SG"},
		{Path: "properties.compute.instance.has_key_pair", Required: false,
			Doc: "key-pair attachment signal"},
		{Path: "properties.compute.encryption.ebs_encrypted", Required: false,
			Doc: "EBS-encryption audit; sparse for instance-store-only types"},
	},
}

func init() { Register(ec2InstanceSchema) }
