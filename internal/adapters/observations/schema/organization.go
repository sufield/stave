package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_organization — 8 controls. The SCP deny/restrict signals are the core
// family; absence of these silently false-PASSes the SCP-guardrail controls.
var organizationSchema = Schema{
	AssetType: kernel.AssetType("aws_organization"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every organization control gates on this (kind=organization)"},
		{Path: "properties.identity.scp.denies_leave_org", Required: true,
			Doc: "leave-org SCP deny — foundational guardrail signal controls gate on"},
		{Path: "properties.identity.scp.denies_root_access_key", Required: true,
			Doc: "root-access-key SCP deny — foundational guardrail signal"},
		{Path: "properties.identity.scp.restricts_regions", Required: true,
			Doc: "region-restriction SCP signal — foundational guardrail signal"},
		{Path: "properties.identity.scp.has_restrictive_policies", Required: false,
			Doc: "aggregate restrictive-policy flag; summary signal, sparse"},
		{Path: "properties.identity.scp.denies_cloudtrail_modify", Required: false,
			Doc: "CloudTrail-modify SCP deny; per-service deny, only when policy present"},
		{Path: "properties.identity.scp.denies_guardduty_disable", Required: false,
			Doc: "GuardDuty-disable SCP deny; per-service deny, only when policy present"},
		{Path: "properties.identity.scp.denies_iam_escalation", Required: false,
			Doc: "IAM-escalation SCP deny; per-service deny, only when policy present"},
		{Path: "properties.identity.scp.has_invalid_actions", Required: false,
			Doc: "SCP references non-existent IAM actions (validated against iamauth registry)"},
		{Path: "properties.identity.scp.has_data_perimeter_s3", Required: false,
			Doc: "SCP enforces S3 data perimeter via aws:ResourceOrgID on write operations"},
	},
}

func init() { Register(organizationSchema) }
