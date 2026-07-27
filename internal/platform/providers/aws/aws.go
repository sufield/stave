// Package aws is the AWS provider's registration entrypoint.
// Calling Register from the CLI's startup wires AWS-specific values
// (URI schemes, principal suffixes, encryption algorithms, banned
// credential env vars, cloud permission sets, observation source
// types) into the kernel's vendor-neutral registries, and pulls in
// the AWS S3 compliance controls via a blank import so their init()
// runs.
//
// The kernel's Register* functions are all idempotent, so calling
// Register more than once is safe. Tests that need the AWS provider
// loaded should call Register from a TestMain or init_test.go.
package aws

import (
	"github.com/sufield/stave/internal/core/evaluation/derive"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// AlgorithmAWSKMS is the AWS KMS-managed encryption algorithm.
// Defined here (not in core/kernel) because it is vendor-specific:
// the kernel is vendor-neutral and surfaces only AlgorithmAES256
// and AlgorithmNone as built-in cryptographic primitives.
// Register adds this algorithm to kernel.ParseAlgorithm so callers
// can parse the wire-format value.
const AlgorithmAWSKMS kernel.EncryptionAlgorithm = "aws:kms"

// SourceTypeAWSS3Snapshot is the canonical source type for AWS S3
// snapshot observations produced by the adapters/aws/s3 extractor.
// The constant lives in the AWS provider package (not in the
// kernel) so vendor-neutral observation handling has no AWS
// dependency.
const SourceTypeAWSS3Snapshot kernel.ObservationSourceType = "aws-s3-snapshot"

// Register wires the AWS provider into Stave's kernel registries.
// Call once during CLI startup (cmd.NewApp). Idempotent and
// concurrent-safe; subsequent calls are no-ops because each
// kernel.Register* function deduplicates.
func Register() {
	kernel.RegisterURIScheme("arn:")
	kernel.RegisterPrincipalSuffix(".amazonaws.com")
	kernel.RegisterEncryptionAlgorithm(AlgorithmAWSKMS)
	kernel.RegisterObservationSourceType(SourceTypeAWSS3Snapshot)

	kernel.RegisterBannedCredentialKeys(
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_PROFILE",
		"AWS_DEFAULT_REGION",
		"AWS_SHARED_CREDENTIALS_FILE",
	)

	kernel.RegisterCloudPermissions(kernel.Vendor("aws"),
		"s3:GetBucketAcl",
		"s3:GetBucketLogging",
		"s3:GetBucketObjectLockConfiguration",
		"s3:GetBucketPolicy",
		"s3:GetBucketPublicAccessBlock",
		"s3:GetBucketTagging",
		"s3:GetBucketVersioning",
		"s3:GetEncryptionConfiguration",
		"s3:GetLifecycleConfiguration",
		"s3:ListAllMyBuckets",
	)

	derive.VPCCIDRTypes.Subnet = "aws_subnet"
	derive.VPCCIDRTypes.SecurityGroup = "aws_ec2_security_group"
	derive.VPCCIDRTypes.NetworkACL = "aws_vpc_network_acl"
	derive.BucketAPTypes.Bucket = "aws_s3_bucket"
	derive.BucketAPTypes.AccessPoint = "aws_s3_access_point"

	remediation.TypeTokens["aws_s3_bucket"] = []remediation.TokenDef{
		{Placeholder: "<bucket>"},
		{Placeholder: "<bucket-name>"},
	}
	remediation.TypeTokens["aws_iam_role"] = []remediation.TokenDef{
		{Placeholder: "<role>"},
		{Placeholder: "<role-name>"},
		{Placeholder: "<role-arn>", UseFullID: true},
	}
	remediation.TypeTokens["aws_iam_user"] = []remediation.TokenDef{
		{Placeholder: "<user>"},
		{Placeholder: "<user-name>"},
		{Placeholder: "<user-arn>", UseFullID: true},
	}
	remediation.TypeTokens["aws_iam_policy"] = []remediation.TokenDef{
		{Placeholder: "<policy>"},
		{Placeholder: "<policy-name>"},
		{Placeholder: "<policy-arn>", UseFullID: true},
	}
	remediation.TypeTokens["aws_eks_cluster"] = []remediation.TokenDef{
		{Placeholder: "<cluster>"},
		{Placeholder: "<cluster-name>"},
	}
	remediation.TypeTokens["aws_kms_key"] = []remediation.TokenDef{
		{Placeholder: "<key-id>"},
		{Placeholder: "<key-arn>", UseFullID: true},
	}
	remediation.TypeTokens["aws_cloudtrail_trail"] = []remediation.TokenDef{
		{Placeholder: "<trail-name>"},
	}
	remediation.TypeTokens["aws_s3_access_point"] = []remediation.TokenDef{
		{Placeholder: "<access-point-name>"},
	}
	remediation.TypeTokens["aws_lambda_function"] = []remediation.TokenDef{
		{Placeholder: "<function>"},
		{Placeholder: "<function-name>"},
	}
	remediation.TypeTokens["aws_ecs_service"] = []remediation.TokenDef{
		{Placeholder: "<service>"},
		{Placeholder: "<service-name>"},
	}
	remediation.TypeTokens["aws_vpc"] = []remediation.TokenDef{
		{Placeholder: "<vpc-id>"},
	}
	remediation.TypeTokens["aws_sqs_queue"] = []remediation.TokenDef{
		{Placeholder: "<queue>"},
		{Placeholder: "<queue-name>"},
	}
}
