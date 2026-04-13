// Package controldata holds the embedded built-in control YAML files.
//
// The embedded/ directory is populated at build time by "make sync-controls",
// which copies canonical control definitions from the top-level controls/
// directory. The embed.FS is exported so that adapter and test packages can
// access the bundled controls without knowing the physical file layout.
package controldata

import "embed"

//go:embed embedded/s3/**/*.yaml embedded/iam/**/*.yaml embedded/gcs/**/*.yaml embedded/dns/**/*.yaml embedded/vpc/**/*.yaml embedded/ec2/**/*.yaml embedded/rds/**/*.yaml embedded/elb/**/*.yaml embedded/k8s/**/*.yaml embedded/backup/**/*.yaml embedded/apigateway/**/*.yaml embedded/autoscaling/**/*.yaml embedded/cloudformation/**/*.yaml embedded/cloudtrail/**/*.yaml embedded/cloudwatch/**/*.yaml embedded/cognito/**/*.yaml embedded/config/**/*.yaml embedded/dynamodb/**/*.yaml embedded/ecr/**/*.yaml embedded/elasticache/**/*.yaml embedded/guardduty/**/*.yaml embedded/kms/**/*.yaml embedded/opensearch/**/*.yaml embedded/route53/**/*.yaml embedded/secretsmanager/**/*.yaml embedded/securityhub/**/*.yaml embedded/sns/**/*.yaml embedded/sqs/**/*.yaml embedded/efs/**/*.yaml embedded/exposure/**/*.yaml embedded/waf/**/*.yaml embedded/guardrail/*.yaml embedded/lambda/**/*.yaml embedded/eks/*.yaml embedded/ecs/**/*.yaml

// FS provides read-only access to the embedded built-in control YAML files.
var FS embed.FS
