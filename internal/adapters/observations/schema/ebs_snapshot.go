package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_ebs_snapshot — 12 controls. compute.kind is the discriminator;
// the encryption and sharing signals drive the snapshot-exposure and
// ghost-account families.
var ebsSnapshotSchema = Schema{
	AssetType: kernel.AssetType("aws_ebs_snapshot"),
	Fields: []FieldRequirement{
		{Path: "properties.compute.kind", Required: true,
			Doc: "type discriminator; every EBS-snapshot control gates on this"},
		{Path: "properties.compute.encrypted", Required: true,
			Doc: "snapshot-encryption detection — foundational for encrypt-at-rest controls"},
		{Path: "properties.compute.is_public", Required: true,
			Doc: "public-exposure signal; core for the snapshot-leak family"},
		{Path: "properties.compute.access.has_cross_account_share", Required: true,
			Doc: "cross-account-share detection; drives the sharing-exposure controls"},
		{Path: "properties.compute.snapshot.source_ami_deregistered", Required: false,
			Doc: "deregistered-source-AMI audit; sparse for non-AMI snapshots"},
		{Path: "properties.compute.ebs.has_decommissioned_account", Required: false,
			Doc: "ghost-account share signal; populated only when a share target is decommissioned"},
		{Path: "properties.compute.ebs.snapshot_is_stale", Required: false,
			Doc: "stale-snapshot hygiene check; age-gated"},
		{Path: "properties.compute.ebs.snapshot_shared_with_nonprod", Required: false,
			Doc: "non-prod-share audit; sparse unless cross-environment sharing is present"},
	},
}

func init() { Register(ebsSnapshotSchema) }
