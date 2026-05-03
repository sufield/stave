package aws_test

import (
	"slices"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/providers/aws"
)

// External _test package so we can import providers/aws without
// creating a production-time cycle (aws imports core/kernel).

func TestRegister_SeedsBannedCredentialKeys(t *testing.T) {
	aws.Register()
	keys := kernel.DefaultPolicy().BannedCredentialKeys()
	for _, want := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_PROFILE",
		"AWS_DEFAULT_REGION",
		"AWS_SHARED_CREDENTIALS_FILE",
	} {
		if !slices.Contains(keys, want) {
			t.Errorf("after aws.Register, %q missing from DefaultPolicy().BannedCredentialKeys()", want)
		}
	}
}

func TestRegister_SeedsAWSCloudPermissions(t *testing.T) {
	aws.Register()
	perms := kernel.DefaultPolicy().ProviderPermissions(kernel.Vendor("aws"))
	for _, want := range []string{
		"s3:GetBucketAcl",
		"s3:GetBucketPolicy",
		"s3:GetBucketPublicAccessBlock",
		"s3:GetEncryptionConfiguration",
		"s3:ListAllMyBuckets",
	} {
		if !slices.Contains(perms, want) {
			t.Errorf("after aws.Register, %q missing from ProviderPermissions(\"aws\")", want)
		}
	}
}

func TestRegister_IsIdempotent(t *testing.T) {
	aws.Register()
	first := len(kernel.DefaultPolicy().BannedCredentialKeys())
	aws.Register()
	aws.Register()
	if got := len(kernel.DefaultPolicy().BannedCredentialKeys()); got != first {
		t.Errorf("Register should be idempotent: first=%d after-extra-calls=%d", first, got)
	}
}

func TestAlgorithmAWSKMS_ParseRoundTrip(t *testing.T) {
	aws.Register()
	got, err := kernel.ParseAlgorithm("aws:kms")
	if err != nil {
		t.Fatalf("ParseAlgorithm(\"aws:kms\") error = %v after aws.Register", err)
	}
	if got != aws.AlgorithmAWSKMS {
		t.Errorf("ParseAlgorithm(\"aws:kms\") = %v, want %v", got, aws.AlgorithmAWSKMS)
	}
	// Sanity: case-insensitive normalisation still works.
	if _, err := kernel.ParseAlgorithm("AWS:KMS"); err != nil {
		t.Errorf("ParseAlgorithm(\"AWS:KMS\") error = %v after aws.Register", err)
	}
}

func TestAlgorithmAWSKMS_String(t *testing.T) {
	if aws.AlgorithmAWSKMS.String() != "aws:kms" {
		t.Errorf("AlgorithmAWSKMS.String() = %q, want %q", aws.AlgorithmAWSKMS.String(), "aws:kms")
	}
}

func TestSourceTypeAWSS3Snapshot_String(t *testing.T) {
	if aws.SourceTypeAWSS3Snapshot.String() != "aws-s3-snapshot" {
		t.Errorf("SourceTypeAWSS3Snapshot.String() = %q, want %q",
			aws.SourceTypeAWSS3Snapshot.String(), "aws-s3-snapshot")
	}
}

func TestSourceTypeAWSS3Snapshot_RegisteredViaRegister(t *testing.T) {
	aws.Register()
	known := kernel.KnownObservationSourceTypes()
	if !slices.Contains(known, aws.SourceTypeAWSS3Snapshot) {
		t.Errorf("after aws.Register, %q missing from KnownObservationSourceTypes()", aws.SourceTypeAWSS3Snapshot)
	}
}
