package graph

import "testing"

func TestToResourceClass_AllTaxonomy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		providerType string
		want         string
	}{
		{"aws_s3_bucket", "storage"},
		{"s3_bucket", "storage"},
		{"aws_rds_instance", "database"},
		{"aws_dynamodb_table", "database"},
		{"aws_lambda_function", "compute"},
		{"aws_ec2_instance", "instance"},
		{"aws_ecs_service", "container"},
		{"aws_eks_cluster", "container"},
		{"aws_vpc", "network"},
		{"aws_security_group", "network"},
		{"aws_iam_role", "identity"},
		{"aws_iam_user", "identity"},
		{"aws_kms_key", "key"},
		{"aws_secretsmanager_secret", "secret"},
		{"aws_cloudfront_distribution", "cdn"},
		{"aws_route53_zone", "dns"},
		{"aws_ecr_repository", "registry"},
		{"aws_sqs_queue", "queue"},
		{"aws_sns_topic", "queue"},
		{"aws_cloudtrail_trail", "log"},
		{"aws_cloudwatch_log_group", "log"},
		{"aws_config_recorder", "log"},
		{"aws_guardduty_detector", "log"},
		{"aws_cognito_user_pool", "identity"},
		{"aws_apigateway_stage", "network"},
		{"aws_backup_resource", "storage"},
	}
	for _, tt := range tests {
		got := ToResourceClass(tt.providerType)
		if got != tt.want {
			t.Errorf("ToResourceClass(%q) = %q, want %q", tt.providerType, got, tt.want)
		}
	}
}

func TestToResourceClass_Unknown(t *testing.T) {
	t.Parallel()
	got := ToResourceClass("completely_unknown_type")
	if got != "unknown" {
		t.Errorf("unknown type should return 'unknown', got %q", got)
	}
}

// TestToResourceClass_CompoundTokens covers provider_types whose
// rule key is a multi-token literal (virtual_machine, compute_engine,
// security_group, key_vault, service_bus, front_door). These cannot
// match through the exact-token path because token splitting breaks
// the compound apart; they resolve via the substring fallback. The
// test fixes that contract so a future "single-token-only" refactor
// of ToResourceClass cannot silently drop these mappings.
func TestToResourceClass_CompoundTokens(t *testing.T) {
	t.Parallel()
	tests := []struct {
		providerType string
		want         string
	}{
		{"azure_virtual_machine", "instance"},
		{"azure_virtual_machine_scale_set", "instance"},
		{"gcp_compute_engine_instance", "instance"},
		{"aws_security_group", "network"},
		{"azure_key_vault", "key"},
		// azure_key_vault_secret is the secret stored INSIDE the vault,
		// not the vault itself — the single-token `secret` rule wins
		// over the compound `key_vault` fallback, which is the correct
		// classification for the resource (secret material, not the
		// HSM). The vault container surfaces as `azure_key_vault`.
		{"azure_key_vault_secret", "secret"},
		{"azure_service_bus_queue", "queue"},
		{"azure_front_door_profile", "cdn"},
	}
	for _, tt := range tests {
		got := ToResourceClass(tt.providerType)
		if got != tt.want {
			t.Errorf("ToResourceClass(%q) = %q, want %q", tt.providerType, got, tt.want)
		}
	}
}
