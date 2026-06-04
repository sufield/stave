package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_iam_account — 8 controls. Root-account hygiene signals are the core
// family; absence silently false-PASSes the root-usage and root-MFA controls.
var iamAccountSchema = Schema{
	AssetType: kernel.AssetType("aws_iam_account"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every account-level control gates on this (kind=account)"},
		{Path: "properties.identity.root.mfa_enabled", Required: true,
			Doc: "root-MFA detection — foundational for the root-MFA controls"},
		{Path: "properties.identity.root.has_access_keys", Required: true,
			Doc: "root-access-key presence — foundational for the no-root-key control"},
		{Path: "properties.identity.root.last_used_days", Required: true,
			Doc: "root last-used recency — foundational for root-usage controls"},
		{Path: "properties.identity.root.hardware_mfa", Required: false,
			Doc: "hardware-MFA flag; refines MFA audit, sparse when MFA absent"},
		{Path: "properties.identity.certificates.has_expired", Required: false,
			Doc: "expired-certificate signal; only meaningful when certificates exist"},
		{Path: "properties.identity.support_role.exists", Required: false,
			Doc: "support-role existence; feature-gated audit signal"},
		{Path: "properties.identity.policies.cloudshell_unrestricted", Required: false,
			Doc: "unrestricted-CloudShell signal; sparse, policy-dependent"},
	},
}

func init() { Register(iamAccountSchema) }
