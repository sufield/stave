package schema

import "github.com/sufield/stave/internal/core/kernel"

// aws_cognito_account — 10 controls. identity.kind is the type discriminator;
// the cognito.metrics_* and cognito.alarm_* flags drive the account-level
// detection-coverage family (CloudWatch metrics and alarms on Cognito events).
var cognitoAccountSchema = Schema{
	AssetType: kernel.AssetType("aws_cognito_account"),
	Fields: []FieldRequirement{
		{Path: "properties.identity.kind", Required: true,
			Doc: "type discriminator; every account-level control gates on this"},
		{Path: "properties.identity.cognito.metrics_logins_tracked", Required: true,
			Doc: "login-metrics presence; foundational — every alarm control assumes this"},
		{Path: "properties.identity.cognito.alarm_delete_user_pool", Required: true,
			Doc: "DeleteUserPool alarm; detection of the most disruptive Cognito event"},
		{Path: "properties.identity.cognito.alarm_failed_auth_spike", Required: true,
			Doc: "failed-auth-spike alarm; core credential-attack detection signal"},
		{Path: "properties.identity.cognito.alarm_set_risk_config", Required: false,
			Doc: "SetRiskConfiguration alarm; sparse advanced-security-mode signal"},
		{Path: "properties.identity.cognito.alarm_create_identity_pool_unauth", Required: false,
			Doc: "unauth-pool-creation alarm; feature-gated on identity-pool usage"},
		{Path: "properties.identity.cognito.alarm_mfa_failure_spike", Required: false,
			Doc: "MFA-failure-spike alarm; only meaningful when MFA enforced"},
	},
}

func init() { Register(cognitoAccountSchema) }
