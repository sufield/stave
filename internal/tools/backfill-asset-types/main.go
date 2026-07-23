// Command backfill-asset-types adds applicable_asset_types to control
// YAML files that lack it, derived from the control ID prefix.
//
// Usage:
//
//	go run ./internal/tools/backfill-asset-types -controls controls/
//	go run ./internal/tools/backfill-asset-types -controls controls/ -dry-run
//	go run ./internal/tools/backfill-asset-types -controls controls/s3/
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// prefixToAssetTypes maps control ID service prefixes to their primary
// asset types. Prefixes not listed here are skipped — add entries as
// confidence in the mapping grows.
var prefixToAssetTypes = map[string][]string{
	"S3":             {"aws_s3_bucket"},
	"EC2":            {"aws_ec2_instance"},
	"RDS":            {"aws_rds_instance"},
	"IAM":            {"aws_iam_user", "aws_iam_role"},
	"VPC":            {"aws_vpc"},
	"EKS":            {"aws_eks_cluster"},
	"ECS":            {"aws_ecs_task_definition"},
	"LAMBDA":         {"aws_lambda_function"},
	"CLOUDTRAIL":     {"aws_cloudtrail_trail"},
	"CLOUDWATCH":     {"aws_cloudwatch_alarm"},
	"CLOUDFRONT":     {"aws_cloudfront_distribution"},
	"KMS":            {"aws_kms_key"},
	"DYNAMODB":       {"aws_dynamodb_table"},
	"SQS":            {"aws_sqs_queue"},
	"SNS":            {"aws_sns_topic"},
	"ELB":            {"aws_elb"},
	"COGNITO":        {"aws_cognito_user_pool"},
	"BEDROCK":        {"aws_bedrock_model"},
	"APIGATEWAY":     {"aws_apigateway_rest_api"},
	"CONFIG":         {"aws_config_recorder"},
	"SECRETS":        {"aws_secretsmanager_secret"},
	"ROUTE53":        {"aws_route53_hosted_zone"},
	"K8S":            {"k8s_resource"},
	"BACKUP":         {"aws_backup_vault"},
	"WAF":            {"aws_waf_web_acl"},
	"AUTOSCALING":    {"aws_autoscaling_group"},
	"CLOUDFORMATION": {"aws_cloudformation_stack"},
	"ELASTICACHE":    {"aws_elasticache_cluster"},
	"GUARDDUTY":      {"aws_guardduty_detector"},
	"SECURITYHUB":    {"aws_securityhub_hub"},
	"SHIELD":         {"aws_shield_subscription"},
	"OPENSEARCH":     {"aws_opensearch_domain"},
	"STEPFUNCTIONS":  {"aws_stepfunctions_state_machine"},
	"EVENTBRIDGE":    {"aws_eventbridge_rule"},
	"ORG":            {"aws_organization"},
	"ACMPCA":         {"aws_acmpca_certificate_authority"},
	"SAGEMAKER":      {"aws_sagemaker_notebook"},
	"LIGHTSAIL":      {"aws_lightsail_instance"},
}

var idRe = regexp.MustCompile(`(?m)^id:\s+CTL\.([A-Z0-9]+)\.`)
var assetTypesRe = regexp.MustCompile(`(?m)^applicable_asset_types:`)

func main() {
	controlsDir := flag.String("controls", "controls", "control catalog directory")
	dryRun := flag.Bool("dry-run", false, "preview changes without writing")
	flag.Parse()

	var updated, skipped, alreadySet int

	err := filepath.Walk(*controlsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yaml") || strings.HasPrefix(filepath.Base(path), "_") {
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", path, readErr)
		}
		content := string(data)

		if assetTypesRe.MatchString(content) {
			lines := strings.SplitSeq(content, "\n")
			for line := range lines {
				trimmed := strings.TrimSpace(line)
				if after, ok := strings.CutPrefix(trimmed, "applicable_asset_types:"); ok {
					rest := after
					rest = strings.TrimSpace(rest)
					if rest != "" && rest != "[]" {
						alreadySet++
						return nil
					}
				}
			}
		}

		m := idRe.FindStringSubmatch(content)
		if m == nil {
			skipped++
			return nil
		}
		prefix := m[1]
		types, ok := prefixToAssetTypes[prefix]
		if !ok {
			skipped++
			return nil
		}

		var typesYAML string
		if len(types) == 1 {
			typesYAML = fmt.Sprintf("applicable_asset_types: [%s]", types[0])
		} else {
			typesYAML = fmt.Sprintf("applicable_asset_types: [%s]", strings.Join(types, ", "))
		}

		var newContent string
		if assetTypesRe.MatchString(content) {
			newContent = assetTypesRe.ReplaceAllString(content, typesYAML)
		} else {
			lines := strings.Split(content, "\n")
			var out []string
			inserted := false
			for _, line := range lines {
				out = append(out, line)
				if !inserted && strings.HasPrefix(line, "id:") {
					out = append(out, typesYAML)
					inserted = true
				}
			}
			if !inserted {
				skipped++
				return nil
			}
			newContent = strings.Join(out, "\n")
		}

		if *dryRun {
			fmt.Printf("WOULD UPDATE %s → %s\n", path, typesYAML)
		} else {
			if writeErr := os.WriteFile(path, []byte(newContent), info.Mode()); writeErr != nil {
				return fmt.Errorf("write %s: %w", path, writeErr)
			}
		}
		updated++
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSummary: %d updated, %d already set, %d skipped (no mapping or no ID)\n", updated, alreadySet, skipped)
}
