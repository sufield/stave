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
