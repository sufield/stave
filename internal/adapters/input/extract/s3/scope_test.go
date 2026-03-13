package s3

import (
	"testing"

	"github.com/sufield/stave/internal/domain/kernel"
)

func TestScopeConfigHealthTags(t *testing.T) {
	cfg := DefaultScopeConfig()

	// Should match DataDomain=health
	tags1 := map[string]string{"DataDomain": "health"}
	if !cfg.IsHealthBucket(tags1, "bucket1") {
		t.Error("expected match for DataDomain=health")
	}

	// Should match containsPHI=true
	tags2 := map[string]string{"containsPHI": "true"}
	if !cfg.IsHealthBucket(tags2, "bucket2") {
		t.Error("expected match for containsPHI=true")
	}

	// Should not match other tags
	tags3 := map[string]string{"DataDomain": "marketing"}
	if cfg.IsHealthBucket(tags3, "bucket3") {
		t.Error("expected no match for DataDomain=marketing")
	}

	// Should not match empty tags
	if cfg.IsHealthBucket(nil, "bucket4") {
		t.Error("expected no match for nil tags")
	}
}

func TestScopeConfigAllowlist(t *testing.T) {
	cfg := &ScopeConfig{
		BucketAllowlist: []string{"allowed-bucket", "arn:aws:s3:::another-allowed"},
	}

	// Should match by name
	if !cfg.IsHealthBucket(nil, "allowed-bucket") {
		t.Error("expected match for allowlisted bucket name")
	}

	// Should match ARN to name
	if !cfg.IsHealthBucket(nil, "another-allowed") {
		t.Error("expected match for allowlisted ARN's bucket name")
	}

	// Should not match unlisted bucket
	if cfg.IsHealthBucket(nil, "not-allowed") {
		t.Error("expected no match for non-allowlisted bucket")
	}
}

func TestScopeConfigIncludeAll(t *testing.T) {
	cfg := &ScopeConfig{IncludeAll: true}

	// Should match everything
	if !cfg.IsHealthBucket(nil, "any-bucket") {
		t.Error("expected match with IncludeAll=true")
	}
	if !cfg.IsHealthBucket(map[string]string{"foo": "bar"}, "other-bucket") {
		t.Error("expected match with IncludeAll=true regardless of tags")
	}
}

func TestScopeConfigCaseInsensitiveTags(t *testing.T) {
	cfg := DefaultScopeConfig()

	// Case-insensitive value matching
	tags := map[string]string{"containsPHI": "TRUE"}
	if !cfg.IsHealthBucket(tags, "bucket") {
		t.Error("expected case-insensitive match for TRUE")
	}

	tags2 := map[string]string{"DataDomain": "HEALTH"}
	if !cfg.IsHealthBucket(tags2, "bucket") {
		t.Error("expected case-insensitive match for HEALTH")
	}
}

func TestMatchesBucket(t *testing.T) {
	tests := []struct {
		pattern  string
		bucket   string
		expected bool
	}{
		{"my-bucket", "my-bucket", true},
		{"my-bucket", "other-bucket", false},
		{"arn:aws:s3:::my-bucket", "my-bucket", true},
		{"my-bucket", "arn:aws:s3:::my-bucket", true},
		{"arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket", true},
		{"MY-BUCKET", "my-bucket", true}, // case insensitive
	}

	for _, tc := range tests {
		result := kernel.NewBucketRef(tc.pattern).Equals(kernel.NewBucketRef(tc.bucket))
		if result != tc.expected {
			t.Errorf("matchesBucket(%q, %q) = %v, want %v", tc.pattern, tc.bucket, result, tc.expected)
		}
	}
}
