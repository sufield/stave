package output_test

import (
	"testing"

	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

func TestSanitizeBaselineEntries_NilSanitizer(t *testing.T) {
	entries := []evaluation.BaselineEntry{{AssetID: "res-1"}}
	result := output.SanitizeBaselineEntries(nil, entries)
	if result[0].AssetID != "res-1" {
		t.Error("expected unchanged entries for nil sanitizer")
	}
}

func TestSanitizeBaselineEntries_Empty(t *testing.T) {
	s := sanitize.New(sanitize.WithIDSanitization(true))
	result := output.SanitizeBaselineEntries(s, nil)
	if result != nil {
		t.Error("expected nil for nil entries")
	}
}

func TestSanitizeBaselineEntries_WithEntries(t *testing.T) {
	s := sanitize.New(sanitize.WithIDSanitization(true))
	entries := []evaluation.BaselineEntry{
		{ControlID: "CTL.A", AssetID: "secret-bucket"},
		{ControlID: "CTL.B", AssetID: "other-bucket"},
	}
	result := output.SanitizeBaselineEntries(s, entries)
	if len(result) != 2 {
		t.Fatalf("len = %d", len(result))
	}
	if result[0].AssetID == "secret-bucket" {
		t.Error("expected sanitized asset ID")
	}
	if result[0].ControlID != "CTL.A" {
		t.Error("control ID should be unchanged")
	}
}

func TestSanitizeObservationDelta_NilSanitizer(t *testing.T) {
	delta := asset.ObservationDelta{
		Changes: []asset.Diff{{AssetID: "res-1"}},
	}
	result := output.SanitizeObservationDelta(nil, delta)
	if result.Changes[0].AssetID != "res-1" {
		t.Error("expected unchanged delta for nil sanitizer")
	}
}

func TestSanitizeObservationDelta_EmptyChanges(t *testing.T) {
	s := sanitize.New(sanitize.WithIDSanitization(true))
	delta := asset.ObservationDelta{}
	result := output.SanitizeObservationDelta(s, delta)
	if len(result.Changes) != 0 {
		t.Error("expected empty changes")
	}
}

func TestSanitizeObservationDelta_WithChanges(t *testing.T) {
	s := sanitize.New(sanitize.WithIDSanitization(true))
	delta := asset.ObservationDelta{
		Changes: []asset.Diff{
			{AssetID: "secret-bucket", ChangeType: asset.ChangeAdded},
		},
	}
	result := output.SanitizeObservationDelta(s, delta)
	if len(result.Changes) != 1 {
		t.Fatalf("len = %d", len(result.Changes))
	}
	if result.Changes[0].AssetID == "secret-bucket" {
		t.Error("expected sanitized asset ID")
	}
}

// Ensure exports used in tests are from the right packages.
var _ kernel.Sanitizer = sanitize.New()
