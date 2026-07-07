package awsmeta

import (
	"slices"
	"testing"
)

func TestExtractSchema_KnownService(t *testing.T) {
	schema, err := ExtractSchema("s3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !schema.Available {
		t.Fatal("expected s3 to be available")
	}
	if len(schema.Operations) == 0 {
		t.Fatal("expected operations for s3")
	}

	hasDescribe := slices.ContainsFunc(schema.Operations, func(op Operation) bool {
		return op.Type == "Describe" || op.Type == "Get"
	})
	if !hasDescribe {
		t.Error("expected Describe/Get operations for s3")
	}
}

func TestExtractSchema_UnknownService(t *testing.T) {
	schema, err := ExtractSchema("nonexistent-service-xyz-9999")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if schema.Available {
		t.Error("expected unknown service to be unavailable")
	}
}

func TestExtractSchema_S3_HasEncryptionFields(t *testing.T) {
	schema, err := ExtractSchema("s3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, op := range schema.Operations {
		if op.Name == "GetBucketEncryption" {
			found = true
			hasRules := slices.ContainsFunc(op.Fields, func(f Field) bool {
				return f.Path == "ServerSideEncryptionConfiguration.Rules"
			})
			if !hasRules {
				t.Error("expected ServerSideEncryptionConfiguration.Rules field")
			}
			break
		}
	}
	if !found {
		t.Error("expected GetBucketEncryption operation")
	}
}

func TestExtractSchema_ACM_HasCertificateFields(t *testing.T) {
	schema, err := ExtractSchema("acm")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !schema.Available {
		t.Fatal("expected acm to be available")
	}

	found := false
	for _, op := range schema.Operations {
		if op.Name == "DescribeCertificate" {
			found = true
			hasArn := slices.ContainsFunc(op.Fields, func(f Field) bool {
				return f.Path == "Certificate.CertificateArn"
			})
			if !hasArn {
				t.Error("expected Certificate.CertificateArn field")
			}
			break
		}
	}
	if !found {
		t.Error("expected DescribeCertificate operation")
	}
}

func TestClassifyOp(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"DescribeBucket", "Describe"},
		{"GetBucketEncryption", "Get"},
		{"ListBuckets", "List"},
		{"PutBucketPolicy", ""},
		{"DeleteBucket", ""},
		{"CreateBucket", ""},
	}
	for _, tt := range tests {
		if got := classifyOp(tt.name); got != tt.want {
			t.Errorf("classifyOp(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
