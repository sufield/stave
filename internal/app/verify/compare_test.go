package verify

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestCompare_NoFindings(t *testing.T) {
	result, err := Compare(CompareRequest{
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RemainingCount != 0 {
		t.Fatalf("remaining = %d", result.RemainingCount)
	}
	if result.IntroducedCount != 0 {
		t.Fatalf("introduced = %d", result.IntroducedCount)
	}
}

func TestCompare_AllResolved(t *testing.T) {
	before := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.TEST.001"), AssetID: asset.ID("bucket-a")},
	}
	result, err := Compare(CompareRequest{
		BeforeFindings:    before,
		AfterFindings:     nil,
		BeforeSnapshots:   2,
		AfterSnapshots:    2,
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RemainingCount != 0 {
		t.Fatalf("remaining = %d", result.RemainingCount)
	}
	if result.IntroducedCount != 0 {
		t.Fatalf("introduced = %d", result.IntroducedCount)
	}
	if result.Verification == nil {
		t.Fatal("verification should not be nil")
	}
	if result.Verification.Summary.Resolved != 1 {
		t.Fatalf("resolved = %d, want 1", result.Verification.Summary.Resolved)
	}
}

func TestCompare_WithRemaining(t *testing.T) {
	finding := evaluation.Finding{
		ControlID: kernel.ControlID("CTL.TEST.001"),
		AssetID:   asset.ID("bucket-a"),
	}
	result, err := Compare(CompareRequest{
		BeforeFindings:    []evaluation.Finding{finding},
		AfterFindings:     []evaluation.Finding{finding},
		BeforeSnapshots:   2,
		AfterSnapshots:    2,
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RemainingCount != 1 {
		t.Fatalf("remaining = %d, want 1", result.RemainingCount)
	}
}

func TestCompare_WithIntroduced(t *testing.T) {
	result, err := Compare(CompareRequest{
		BeforeFindings: nil,
		AfterFindings: []evaluation.Finding{
			{ControlID: kernel.ControlID("CTL.NEW.001"), AssetID: asset.ID("bucket-new")},
		},
		BeforeSnapshots:   2,
		AfterSnapshots:    2,
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IntroducedCount != 1 {
		t.Fatalf("introduced = %d, want 1", result.IntroducedCount)
	}
}

func TestCompare_WithSanitizer(t *testing.T) {
	before := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.TEST.001"), AssetID: asset.ID("bucket-a")},
	}
	result, err := Compare(CompareRequest{
		BeforeFindings:    before,
		AfterFindings:     nil,
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
		Sanitizer:         testSanitizer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Verify that the resolved entries have sanitized asset IDs
	if len(result.Verification.Resolved) != 1 {
		t.Fatalf("expected 1 resolved entry, got %d", len(result.Verification.Resolved))
	}
	if string(result.Verification.Resolved[0].AssetID) == "bucket-a" {
		t.Fatal("asset ID should be sanitized")
	}
}

func TestFindingsToEntries_Empty(t *testing.T) {
	entries := findingsToEntries(nil, nil)
	if entries != nil {
		t.Fatal("expected nil for empty findings")
	}
}

func TestFindingsToEntries_NoSanitizer(t *testing.T) {
	findings := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.TEST.001"), AssetID: asset.ID("bucket-a"), AssetType: "aws_s3_bucket"},
	}
	entries := findingsToEntries(nil, findings)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if string(entries[0].AssetID) != "bucket-a" {
		t.Fatalf("asset ID should not be sanitized: %s", entries[0].AssetID)
	}
}

// testSanitizer masks asset IDs for testing.
type testSanitizer struct{}

func (testSanitizer) ID(s string) string    { return "REDACTED-" + s }
func (testSanitizer) Path(s string) string  { return s }
func (testSanitizer) Value(s string) string { return s }
