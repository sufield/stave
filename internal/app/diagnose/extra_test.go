package diagnose

import (
	"context"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
)

func TestFilter_Apply_ByCasesOnly(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: diagnosis.ScenarioEmptyFindings, Signal: "info"},
			{Case: diagnosis.ScenarioViolationEvidence, Signal: "warn"},
		},
	}
	f := Filter{Cases: []string{string(diagnosis.ScenarioEmptyFindings)}}
	result := f.Apply(report)
	if len(result.Issues) != 1 {
		t.Fatalf("len = %d, want 1", len(result.Issues))
	}
	if result.Issues[0].Case != diagnosis.ScenarioEmptyFindings {
		t.Errorf("Case = %q", result.Issues[0].Case)
	}
}

func TestFilter_Apply_BySignalOnly(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: "a", Signal: "WARNING: something"},
			{Case: "b", Signal: "INFO: ok"},
		},
	}
	f := Filter{SignalContains: "warning"}
	result := f.Apply(report)
	if len(result.Issues) != 1 || result.Issues[0].Case != "a" {
		t.Fatalf("filtered = %v", result.Issues)
	}
}

func TestFilter_Apply_TrimmedCases(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: "a", Signal: "x"},
		},
	}
	// Empty trimmed case should be ignored
	f := Filter{Cases: []string{"  ", "a"}}
	result := f.Apply(report)
	if len(result.Issues) != 1 {
		t.Fatalf("len = %d, want 1", len(result.Issues))
	}
}

type stubObsRepo struct{}

func (stubObsRepo) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return appcontracts.LoadResult{}, nil
}

type stubCtlRepo struct{}

func (stubCtlRepo) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return nil, nil
}

func TestNewRun_NilObsRepo(t *testing.T) {
	_, err := NewRun(nil, stubCtlRepo{})
	if err == nil {
		t.Fatal("expected error for nil obs repo")
	}
}

func TestNewRun_NilCtlRepo(t *testing.T) {
	_, err := NewRun(stubObsRepo{}, nil)
	if err == nil {
		t.Fatal("expected error for nil ctl repo")
	}
}

func TestNewRun_ValidRepos(t *testing.T) {
	r, err := NewRun(stubObsRepo{}, stubCtlRepo{})
	if err != nil {
		t.Fatalf("NewRun() error = %v", err)
	}
	if r == nil {
		t.Fatal("NewRun() returned nil")
	}
}

func TestToDiagnosticFindings(t *testing.T) {
	input := []evaluation.Finding{
		{
			ControlID: "CTL.A",
			AssetID:   "res-1",
			Evidence: evaluation.Evidence{
				FirstUnsafeAt:       time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC),
				LastSeenUnsafeAt:    time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC),
				UnsafeDurationHours: 24,
				ThresholdHours:      12,
			},
		},
		{
			ControlID: "CTL.B",
			AssetID:   "res-2",
		},
	}
	result := toDiagnosticFindings(input)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0].ControlID != "CTL.A" {
		t.Errorf("result[0].ControlID = %q", result[0].ControlID)
	}
	if result[0].UnsafeDurationHours != 24 {
		t.Errorf("result[0].UnsafeDurationHours = %f", result[0].UnsafeDurationHours)
	}
	if result[1].AssetID != "res-2" {
		t.Errorf("result[1].AssetID = %q", result[1].AssetID)
	}
}
