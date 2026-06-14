package policy

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

// TestBugHunt_GovCloudAccountIDExtracted proves that the external account ID
// is extracted from a cross-account principal in the AWS GovCloud partition
// (arn:aws-us-gov:...), not only the commercial "aws" partition.
//
// analyzeExternalAccess flags HasExternalAccess=true whenever a statement
// names concrete account ARNs, then calls extractAccountID on each to record
// WHICH account. extractAccountID used accountARNPattern =
// `^arn:aws:iam::(\d{12}):`, which hardcodes the "aws" partition. A GovCloud
// principal arn:aws-us-gov:iam::123456789012:root (or China, arn:aws-cn:...)
// fails the match, so the account ID is silently dropped: the report says
// "this bucket grants cross-account access" but cannot say to whom — a gap
// that matters precisely for the regulated GovCloud/China audience.
//
// Correct behavior: the account ID is extracted regardless of partition.
func TestBugHunt_GovCloudAccountIDExtracted(t *testing.T) {
	t.Parallel()

	policyJSON := `{
		"Version": "2012-10-17",
		"Statement": [{
			"Effect": "Allow",
			"Principal": {"AWS": "arn:aws-us-gov:iam::123456789012:root"},
			"Action": "s3:GetObject",
			"Resource": "arn:aws-us-gov:s3:::my-bucket/*"
		}]
	}`

	doc, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse returned error for valid policy: %v", err)
	}

	result := doc.Assess()

	if !result.HasExternalAccess {
		t.Fatalf("expected HasExternalAccess=true for a cross-account GovCloud principal")
	}
	if len(result.ExternalAccountIDs) != 1 {
		t.Fatalf("expected 1 external account ID extracted from a GovCloud ARN, got %d %v "+
			"(account ID dropped because accountARNPattern hardcodes the 'aws' partition)",
			len(result.ExternalAccountIDs), result.ExternalAccountIDs)
	}
	if result.ExternalAccountIDs[0] != kernel.AccountID("123456789012") {
		t.Errorf("expected account ID 123456789012, got %q", result.ExternalAccountIDs[0])
	}
}
