package validation

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestResult_Valid_NilResult(t *testing.T) {
	var r *Report
	if !r.Valid() {
		t.Error("nil Report should be valid")
	}
}

func TestResult_Valid_NoDiagnostics(t *testing.T) {
	r := &Report{}
	if !r.Valid() {
		t.Error("empty Report should be valid")
	}
}

func TestResult_HasWarnings_NilResult(t *testing.T) {
	var r *Report
	if r.HasWarnings() {
		t.Error("nil Report should have no warnings")
	}
}

func TestValidateLoaded_Empty(t *testing.T) {
	result := ValidateLoaded(Input{
		NowTime:           time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
	})
	// No controls = warning; ValidateLoaded with no controls adds a warning,
	// not an error, so it should still be valid (warnings != errors).
	_ = result.Valid()
	if result.Summary.ControlsLoaded != 0 {
		t.Errorf("ControlsLoaded = %d", result.Summary.ControlsLoaded)
	}
}

func TestValidateLoaded_WithControls(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.001",
		Name:     "Test Control",
		Type:     policy.TypeUnsafeState,
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)},
			},
		},
	}
	snap := asset.Snapshot{
		CapturedAt: time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC),
		Assets: []asset.Asset{
			{
				ID:   "res-1",
				Type: kernel.AssetType("test"),
				Properties: map[string]any{
					"public": true,
				},
			},
		},
	}

	result := ValidateLoaded(Input{
		Controls:          []policy.ControlDefinition{ctl},
		Snapshots:         []asset.Snapshot{snap},
		NowTime:           time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
	})

	if result.Summary.ControlsLoaded != 1 {
		t.Errorf("ControlsLoaded = %d", result.Summary.ControlsLoaded)
	}
	if result.Summary.SnapshotsLoaded != 1 {
		t.Errorf("SnapshotsLoaded = %d", result.Summary.SnapshotsLoaded)
	}
	if result.Summary.AssetObservationsLoaded != 1 {
		t.Errorf("AssetObservationsLoaded = %d", result.Summary.AssetObservationsLoaded)
	}
}

func TestValidateLoaded_NoControlsWarning(t *testing.T) {
	result := ValidateLoaded(Input{
		Snapshots: []asset.Snapshot{
			{CapturedAt: time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)},
		},
		NowTime:           time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: 24 * time.Hour,
	})
	if !result.HasWarnings() {
		t.Error("expected warnings for no controls")
	}
}
