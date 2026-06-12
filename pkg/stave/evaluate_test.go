package stave

import (
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// These exercise the evaluate helpers that moved here from cmd/evaluate.

func TestEvalValidateSchema_Valid(t *testing.T) {
	if err := evalValidateSchema(kernel.SchemaObservation); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEvalValidateSchema_Invalid(t *testing.T) {
	err := evalValidateSchema("obs.v999")
	if err == nil {
		t.Fatal("expected error for invalid schema")
	}
	if !strings.Contains(err.Error(), "unsupported schema version") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEvalExtractBucketName_FromProperties(t *testing.T) {
	snap := asset.Snapshot{Assets: []asset.Asset{
		{ID: "arn:aws:s3:::my-bucket", Properties: map[string]any{"bucket_name": "my-bucket"}},
	}}
	if got := evalExtractBucketName(snap); got != "my-bucket" {
		t.Fatalf("got %q, want my-bucket", got)
	}
}

func TestEvalExtractBucketName_FromAssetID(t *testing.T) {
	snap := asset.Snapshot{Assets: []asset.Asset{
		{ID: "some-id", Properties: map[string]any{}},
	}}
	if got := evalExtractBucketName(snap); got != "some-id" {
		t.Fatalf("got %q, want some-id", got)
	}
}

func TestEvalExtractBucketName_NoAssets(t *testing.T) {
	if got := evalExtractBucketName(asset.Snapshot{}); got != "unknown" {
		t.Fatalf("got %q, want unknown", got)
	}
}

func TestEvalExtractAccountID(t *testing.T) {
	if got := evalExtractAccountID(asset.Snapshot{}); got != "" {
		t.Fatalf("got %q, want empty for snapshot with no assets", got)
	}
	snap := asset.Snapshot{Assets: []asset.Asset{{ID: "arn:aws:s3::123456789012:bucket"}}}
	if got := evalExtractAccountID(snap); got != "123456789012" {
		t.Fatalf("got %q, want 123456789012", got)
	}
}

func TestEvalAllRegistries(t *testing.T) {
	if regs := evalAllRegistries(); len(regs) == 0 {
		t.Fatal("expected at least one registry")
	}
}

func TestEvalResolveNow(t *testing.T) {
	if _, err := evalResolveNow(""); err != nil {
		t.Errorf("empty should default to now, got: %v", err)
	}
	if _, err := evalResolveNow("2026-01-01T00:00:00Z"); err != nil {
		t.Errorf("valid RFC3339 should parse, got: %v", err)
	}
	if _, err := evalResolveNow("not-a-time"); err == nil {
		t.Error("invalid timestamp should error")
	}
}
