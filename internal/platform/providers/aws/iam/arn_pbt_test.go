package iam

import (
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

var (
	partitions = []string{"aws", "aws-cn", "aws-us-gov"}
	services   = []string{"s3", "iam", "ec2", "lambda", "kms", "sts", "dynamodb", "cloudtrail", "logs", "sqs"}
	regions    = []string{"us-east-1", "eu-west-1", "ap-southeast-1", "us-gov-west-1", "cn-north-1", ""}
)

func genValidARN(t *rapid.T) string {
	partition := rapid.SampledFrom(partitions).Draw(t, "partition")
	service := rapid.SampledFrom(services).Draw(t, "service")
	region := rapid.SampledFrom(regions).Draw(t, "region")
	account := rapid.StringMatching(`[0-9]{12}`).Draw(t, "account")
	resource := rapid.StringMatching(`[a-zA-Z0-9/_*.-]{0,64}`).Draw(t, "resource")
	return fmt.Sprintf("arn:%s:%s:%s:%s:%s", partition, service, region, account, resource)
}

func TestPBT_ParseARN_NeverPanics(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.String().Draw(t, "input")
		_ = ParseARN(input)
	})
}

func TestPBT_ParseARN_Roundtrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		partition := rapid.SampledFrom(partitions).Draw(t, "partition")
		service := rapid.SampledFrom(services).Draw(t, "service")
		region := rapid.SampledFrom(regions).Draw(t, "region")
		account := rapid.StringMatching(`[0-9]{12}`).Draw(t, "account")
		// Resource may contain colons (e.g. arn:aws:iam::123:role/path/name)
		resource := rapid.StringMatching(`[a-zA-Z0-9/_*:.-]{0,64}`).Draw(t, "resource")

		arn := fmt.Sprintf("arn:%s:%s:%s:%s:%s", partition, service, region, account, resource)
		parsed := ParseARN(arn)

		if parsed.Partition != partition {
			t.Fatalf("Partition: got %q, want %q (input: %s)", parsed.Partition, partition, arn)
		}
		if parsed.Service != service {
			t.Fatalf("Service: got %q, want %q (input: %s)", parsed.Service, service, arn)
		}
		if parsed.Region != region {
			t.Fatalf("Region: got %q, want %q (input: %s)", parsed.Region, region, arn)
		}
		if parsed.AccountID != account {
			t.Fatalf("AccountID: got %q, want %q (input: %s)", parsed.AccountID, account, arn)
		}
		// Resource may contain colons; the parser splits on the first colon after account.
		// So parsed.Resource == everything after the 5th colon.
		wantResource := resource
		if parsed.Resource != wantResource {
			t.Fatalf("Resource: got %q, want %q (input: %s)", parsed.Resource, wantResource, arn)
		}
	})
}

func TestPBT_ParseARN_InvalidPrefix(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.String().Draw(t, "input")
		if strings.HasPrefix(input, "arn:") {
			return // skip — valid prefix
		}
		parsed := ParseARN(input)
		if parsed != (ARN{}) {
			t.Fatalf("non-arn: prefix %q produced non-zero ARN: %+v", input, parsed)
		}
	})
}

func TestPBT_ParseARN_EmptySegments(t *testing.T) {
	t.Parallel()
	edges := []string{
		"arn:::::",
		"arn:aws::::",
		"arn::s3:::",
		"arn:aws:s3:::bucket-name",
		"arn:aws:s3:::bucket/key/with:colon",
		"arn:aws:iam::123456789012:root",
		"arn:aws:s3:::my-bucket/*",
	}
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.SampledFrom(edges).Draw(t, "edge")
		parsed := ParseARN(input)
		// Just verify no panic. For valid shapes, spot-check structure.
		if input == "arn:aws:s3:::bucket-name" {
			if parsed.Service != "s3" {
				t.Fatalf("expected service=s3, got %q", parsed.Service)
			}
			if parsed.AccountID != "" {
				t.Fatalf("S3 bucket ARN should have empty account, got %q", parsed.AccountID)
			}
			if parsed.Resource != "bucket-name" {
				t.Fatalf("expected resource=bucket-name, got %q", parsed.Resource)
			}
		}
	})
}

func TestPBT_ExtractAccountID_Consistent(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.OneOf(
			rapid.Custom(genValidARN),
			rapid.String(),
		).Draw(t, "input")

		got := ExtractAccountID(input)
		want := ParseARN(input).AccountID
		if got != want {
			t.Fatalf("ExtractAccountID(%q) = %q, ParseARN().AccountID = %q", input, got, want)
		}
	})
}
