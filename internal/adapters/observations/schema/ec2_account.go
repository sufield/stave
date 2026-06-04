package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_ec2_account — 11 controls. Account-scoped pseudo-asset;
// compute.kind is the discriminator and the ebs.* account-default and
// broad-grant signals drive the encryption-default and access-scope families.
var ec2AccountSchema = Schema{
	AssetType: kernel.AssetType("aws_ec2_account"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every EC2-account control gates on this"},
		{Path: "properties.compute.ebs.default_encrypt_enabled", Required: true,
			Doc: "account-default EBS-encryption signal — foundational for the encrypt-default family"},
		{Path: "properties.compute.ebs.modify_snapshot_broadly_granted", Required: true,
			Doc: "broad ModifySnapshotAttribute grant detection; core for the access-scope controls"},
		{Path: "properties.compute.ebs.delete_snapshot_broadly_granted", Required: true,
			Doc: "broad DeleteSnapshot grant detection; core for the access-scope controls"},
		{Path: "properties.compute.ebs.default_uses_cmk", Required: false,
			Doc: "CMK-vs-default-key signal; meaningful only when default encryption is enabled"},
		{Path: "properties.compute.ebs.has_scp_deny_public_snapshot", Required: false,
			Doc: "SCP-guardrail audit; sparse unless an org-level SCP is present"},
		{Path: "properties.compute.ebs.is_org_account", Required: false,
			Doc: "org-membership classification; sparse for standalone accounts"},
		{Path: "properties.compute.ebs.alarm_snapshot_public", Required: false,
			Doc: "CloudWatch-alarm-coverage audit; feature-gated on alarm configuration"},
	},
}

func init() { Register(ec2AccountSchema) }
