package attestation

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestCompare_NoFindings(t *testing.T) {
	result, err := Compare(CompareRequest{
		Now:          time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		SLAThreshold: 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OpenCount != 0 {
		t.Fatalf("open = %d", result.OpenCount)
	}
	if result.RegressionCount != 0 {
		t.Fatalf("regressions = %d", result.RegressionCount)
	}
}

func TestCompare_AllRemediated(t *testing.T) {
	before := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.TEST.001"), AssetID: asset.ID("bucket-a")},
	}
	result, err := Compare(CompareRequest{
		BaselineFindings:  before,
		TargetFindings:    nil,
		BaselineSnapshots: 2,
		TargetSnapshots:   2,
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		SLAThreshold:      24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OpenCount != 0 {
		t.Fatalf("open = %d", result.OpenCount)
	}
	if result.RegressionCount != 0 {
		t.Fatalf("regressions = %d", result.RegressionCount)
	}
	if result.Attestation == nil {
		t.Fatal("attestation should not be nil")
	}
	if result.Attestation.Summary.Remediated != 1 {
		t.Fatalf("remediated = %d, want 1", result.Attestation.Summary.Remediated)
	}
}

func TestCompare_WithOpen(t *testing.T) {
	finding := evaluation.Finding{
		ControlID: kernel.ControlID("CTL.TEST.001"),
		AssetID:   asset.ID("bucket-a"),
	}
	result, err := Compare(CompareRequest{
		BaselineFindings:  []evaluation.Finding{finding},
		TargetFindings:    []evaluation.Finding{finding},
		BaselineSnapshots: 2,
		TargetSnapshots:   2,
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		SLAThreshold:      24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OpenCount != 1 {
		t.Fatalf("open = %d, want 1", result.OpenCount)
	}
}

func TestCompare_WithRegressions(t *testing.T) {
	result, err := Compare(CompareRequest{
		BaselineFindings: nil,
		TargetFindings: []evaluation.Finding{
			{ControlID: kernel.ControlID("CTL.NEW.001"), AssetID: asset.ID("bucket-new")},
		},
		BaselineSnapshots: 2,
		TargetSnapshots:   2,
		Now:               time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		SLAThreshold:      24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RegressionCount != 1 {
		t.Fatalf("regressions = %d, want 1", result.RegressionCount)
	}
}

func TestCompare_WithSanitizer(t *testing.T) {
	before := []evaluation.Finding{
		{ControlID: kernel.ControlID("CTL.TEST.001"), AssetID: asset.ID("bucket-a")},
	}
	result, err := Compare(CompareRequest{
		BaselineFindings: before,
		TargetFindings:   nil,
		Now:              time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		SLAThreshold:     24 * time.Hour,
		Sanitizer:        testSanitizer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Attestation.Remediated) != 1 {
		t.Fatalf("expected 1 remediated entry, got %d", len(result.Attestation.Remediated))
	}
	if string(result.Attestation.Remediated[0].AssetID) == "bucket-a" {
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

type testSanitizer struct{}

func (testSanitizer) ID(s string) string    { return "REDACTED-" + s }
func (testSanitizer) Path(s string) string  { return s }
func (testSanitizer) Value(s string) string { return s }
