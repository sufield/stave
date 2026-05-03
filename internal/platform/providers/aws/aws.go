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
}
