package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_cognito_app_client — 17 controls. identity.kind is the type
// discriminator; the cognito.* OAuth-flow and token-lifetime flags drive
// the implicit-flow, public-client, and refresh-token-TTL control families.
var cognitoAppClientSchema = Schema{
	AssetType: kernel.AssetType("aws_cognito_app_client"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every app-client control gates on this"},
		{Path: "properties.identity.cognito.is_public_client", Required: true,
			Doc: "public-vs-confidential client classification; core privilege signal"},
		{Path: "properties.identity.cognito.has_client_secret", Required: true,
			Doc: "client-secret presence; foundational for confidential-client checks"},
		{Path: "properties.identity.cognito.allows_implicit_flow", Required: true,
			Doc: "OAuth implicit-flow detection; tokens-in-URL-fragment control"},
		{Path: "properties.identity.cognito.refresh_token_too_long", Required: true,
			Doc: "refresh-token-lifetime bound; core long-lived-session control"},
		{Path: "properties.identity.cognito.callback_has_wildcard", Required: false,
			Doc: "wildcard-callback signal; sparse, only when redirect URIs misconfigured"},
		{Path: "properties.identity.cognito.client_attribute_rw_all", Required: false,
			Doc: "broad-attribute read/write signal; feature-gated on attribute scopes"},
		{Path: "properties.identity.security.prevent_user_existence_errors", Required: false,
			Doc: "user-enumeration-hardening flag; sparse advanced-security signal"},
	},
}

func init() { Register(cognitoAppClientSchema) }
