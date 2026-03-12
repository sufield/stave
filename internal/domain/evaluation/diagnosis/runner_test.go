package diagnosis

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// TestRun_NoViolations_ThresholdMismatch tests that diagnostics correctly identify
// when the maximum unsafe threshold exceeds the observed unsafe duration for assets
// that remain unsafe throughout the observation period.
func TestRun_NoViolations_ThresholdMismatch(t *testing.T) {
	// Setup: assets are unsafe for 48h but threshold is 168h
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	snapshots := []asset.Snapshot{
		{
			CapturedAt: baseTime,
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket"), Properties: map[string]any{"public": true}},
			},
		},
		{
			CapturedAt: baseTime.Add(48 * time.Hour),
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket"), Properties: map[string]any{"public": true}},
			},
		},
	}

	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.EXP.DURATION.001",
			Name: "Test",
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{{Field: "properties.public", Op: "eq", Value: true}},
			},
		},
	}

	input := NewInput(snapshots, controls, []evaluation.Finding{}, nil, 168*time.Hour, baseTime.Add(48*time.Hour))

	report := Explain(input)

	// Should detect threshold mismatch
	if len(report.Issues) == 0 {
		t.Error("expected diagnostics for threshold mismatch")
	}

	found := false
	for _, d := range report.Issues {
		if d.Signal == "Threshold exceeds observed unsafe duration" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected threshold mismatch diagnostic")
	}
}

// TestRun_NoViolations_TimeSpanTooShort tests that diagnostics detect when
// the observation time span is shorter than the configured maximum unsafe threshold,
// making it impossible to fully evaluate the control.
func TestRun_NoViolations_TimeSpanTooShort(t *testing.T) {
	// Setup: time span is only 24h but threshold is 168h
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	snapshots := []asset.Snapshot{
		{
			CapturedAt: baseTime,
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket"), Properties: map[string]any{"public": true}},
			},
		},
		{
			CapturedAt: baseTime.Add(24 * time.Hour),
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket"), Properties: map[string]any{"public": true}},
			},
		},
	}

	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.EXP.DURATION.001",
			Name: "Test",
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{{Field: "properties.public", Op: "eq", Value: true}},
			},
		},
	}

	input := NewInput(snapshots, controls, []evaluation.Finding{}, nil, 168*time.Hour, baseTime.Add(24*time.Hour))

	report := Explain(input)

	found := false
	for _, d := range report.Issues {
		if d.Signal == "Time span shorter than threshold" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected time span diagnostic")
	}
}

// TestRun_NoViolations_PredicateMismatch tests that diagnostics identify
// when no assets match the unsafe predicate criteria, indicating the control
// may not be applicable to the current asset set.
func TestRun_NoViolations_PredicateMismatch(t *testing.T) {
	// Setup: no assets match the predicate
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	snapshots := []asset.Snapshot{
		{
			CapturedAt: baseTime,
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket"), Properties: map[string]any{"public": false}},
			},
		},
		{
			CapturedAt: baseTime.Add(200 * time.Hour),
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket"), Properties: map[string]any{"public": false}},
			},
		},
	}

	controls := []policy.ControlDefinition{
		{
			ID:   "CTL.EXP.DURATION.001",
			Name: "Test",
			UnsafePredicate: policy.UnsafePredicate{
				Any: []policy.PredicateRule{{Field: "properties.public", Op: "eq", Value: true}},
			},
		},
	}

	input := NewInput(snapshots, controls, []evaluation.Finding{}, nil, 168*time.Hour, baseTime.Add(200*time.Hour))

	report := Explain(input)

	found := false
	for _, d := range report.Issues {
		if d.Signal == "No resources matched any unsafe_predicate" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected predicate mismatch diagnostic")
	}
}

// TestRun_UnexpectedViolations_NowSkew tests that diagnostics detect
// when the evaluation time (--now) is set before the latest snapshot timestamp,
// which could lead to incomplete or incorrect analysis.
func TestRun_UnexpectedViolations_NowSkew(t *testing.T) {
	// Setup: --now is before latest snapshot
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	latestSnapshot := baseTime.Add(200 * time.Hour)

	snapshots := []asset.Snapshot{
		{CapturedAt: baseTime, Assets: []asset.Asset{{ID: "res:1", Type: kernel.AssetType("storage_bucket")}}},
		{CapturedAt: latestSnapshot, Assets: []asset.Asset{{ID: "res:1", Type: kernel.AssetType("storage_bucket")}}},
	}

	findings := []evaluation.Finding{
		{
			AssetID: "res:1",
			Evidence: evaluation.Evidence{
				FirstUnsafeAt:       baseTime,
				LastSeenUnsafeAt:    latestSnapshot,
				UnsafeDurationHours: 200,
				ThresholdHours:      168,
			},
		},
	}

	input := NewInput(snapshots, []policy.ControlDefinition{{ID: "CTL.TEST"}}, findings, nil, 168*time.Hour, baseTime.Add(100*time.Hour))

	report := Explain(input)

	found := false
	for _, d := range report.Issues {
		if d.Signal == "Evaluation time before latest snapshot" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected now skew diagnostic")
	}
}

// TestRun_Summary tests that the diagnostic report summary correctly
// aggregates counts of snapshots, assets, controls, and calculates the
// total observation time span.
func TestRun_Summary(t *testing.T) {
	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	snapshots := []asset.Snapshot{
		{
			CapturedAt: baseTime,
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket")},
				{ID: "res:2", Type: kernel.AssetType("storage_bucket")},
			},
		},
		{
			CapturedAt: baseTime.Add(240 * time.Hour),
			Assets: []asset.Asset{
				{ID: "res:1", Type: kernel.AssetType("storage_bucket")},
				{ID: "res:2", Type: kernel.AssetType("storage_bucket")},
			},
		},
	}

	controls := []policy.ControlDefinition{
		{ID: "CTL.1", Name: "Test1"},
		{ID: "CTL.2", Name: "Test2"},
	}

	input := NewInput(snapshots, controls, []evaluation.Finding{}, nil, 168*time.Hour, baseTime.Add(240*time.Hour))

	report := Explain(input)

	if report.Summary.TotalSnapshots != 2 {
		t.Errorf("expected 2 snapshots, got %d", report.Summary.TotalSnapshots)
	}
	if report.Summary.TotalAssets != 2 {
		t.Errorf("expected 2 resources, got %d", report.Summary.TotalAssets)
	}
	if report.Summary.TotalControls != 2 {
		t.Errorf("expected 2 controls, got %d", report.Summary.TotalControls)
	}
	if report.Summary.TimeSpan != kernel.Duration(240*time.Hour) {
		t.Errorf("expected 240h time span, got %v", report.Summary.TimeSpan)
	}
}

// TestFormatDuration tests the formatDuration helper function that converts
// time.Duration values to human-readable strings, preferring days for
// durations evenly divisible by 24 hours, otherwise using hours.
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{24 * time.Hour, "1d"},
		{48 * time.Hour, "2d"},
		{168 * time.Hour, "7d"},
		{12 * time.Hour, "12h"},
		{36 * time.Hour, "36h"}, // Not evenly divisible by 24
	}

	for _, tt := range tests {
		result := timeutil.FormatDuration(tt.duration)
		if result != tt.expected {
			t.Errorf("timeutil.FormatDuration(%v) = %s, want %s", tt.duration, result, tt.expected)
		}
	}
}
