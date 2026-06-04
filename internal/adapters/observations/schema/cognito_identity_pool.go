package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_cognito_identity_pool — 16 controls. identity.kind is the type
// discriminator; access.allow_unauthenticated and the cognito.*_role_* flags
// drive the unauth-access, role-mapping, and role-privilege control families.
var cognitoIdentityPoolSchema = Schema{
	AssetType: kernel.AssetType("aws_cognito_identity_pool"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every identity-pool control gates on this"},
		{Path: "properties.identity.access.allow_unauthenticated", Required: true,
			Doc: "unauthenticated-access toggle; foundational anonymous-credentials signal"},
		{Path: "properties.identity.cognito.has_role_mapping", Required: true,
			Doc: "role-mapping presence; core least-privilege-at-credentials-layer signal"},
		{Path: "properties.identity.cognito.auth_role_broad", Required: true,
			Doc: "broad authenticated-role detection; core over-permission signal"},
		{Path: "properties.identity.cognito.auth_role_has_cross_account", Required: true,
			Doc: "cross-account reach via authenticated role; foreign-account control"},
		{Path: "properties.identity.cognito.unauth_role_broad", Required: false,
			Doc: "broad unauthenticated-role signal; only meaningful when unauth enabled"},
		{Path: "properties.identity.cognito.has_ghost_user_pool", Required: false,
			Doc: "dangling-provider signal; sparse, present only with detached providers"},
		{Path: "properties.identity.cognito.provider_validates_audience", Required: false,
			Doc: "OIDC audience-validation flag; feature-gated on configured providers"},
	},
}

func init() { Register(cognitoIdentityPoolSchema) }
