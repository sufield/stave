package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_cognito_user_pool — 58 controls. identity.kind is the type
// discriminator; cognito.trigger_type / has_ghost_trigger drive
// the ghost-trigger and lambda-side controls (10 controls each).
var cognitoUserPoolSchema = Schema{
	AssetType: kernel.AssetType("aws_cognito_user_pool"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every cognito control gates on this"},
		{Path: "properties.identity.cognito.trigger_type", Required: true,
			Doc: "lambda trigger taxonomy; drives the ghost-trigger family"},
		{Path: "properties.identity.cognito.has_ghost_trigger", Required: true,
			Doc: "core ghost-trigger detection signal"},
		{Path: "properties.identity.auth.mfa_enforced", Required: false,
			Doc: "MFA-enforcement audit signal"},
		{Path: "properties.identity.security.blocks_compromised_credentials", Required: false,
			Doc: "advanced-security-mode signal; sparse when ASM disabled"},
		{Path: "properties.identity.security.blocks_risky_sign_ins", Required: false,
			Doc: "advanced-security-mode signal; sparse when ASM disabled"},
	},
}

func init() { Register(cognitoUserPoolSchema) }
