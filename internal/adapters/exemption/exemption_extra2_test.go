package exemption

import (
	"testing"
)

func TestExemptionConfigToDomain_Empty(t *testing.T) {
	y := yamlExemptionConfig{
		Version: "v1",
		Assets:  nil,
	}
	cfg := exemptionConfigToDomain(y)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestExemptionConfigToDomain_WithRules(t *testing.T) {
	y := yamlExemptionConfig{
		Version: "v1",
		Assets: []yamlExemptionRule{
			{Pattern: "bucket-*", Reason: "temp data"},
			{Pattern: "logs-*", Reason: "log buckets"},
		},
	}
	cfg := exemptionConfigToDomain(y)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	// The ExemptionConfig should have the rules
	// Test by checking if a matching pattern exempts an asset
	rule := cfg.ShouldExempt("bucket-test")
	if rule == nil {
		t.Fatal("expected exemption for bucket-test")
	}
	if rule.Reason != "temp data" {
		t.Fatalf("Reason = %q", rule.Reason)
	}
}
