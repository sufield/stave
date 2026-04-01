package diagnose

import (
	"context"
	"errors"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockObsRepo struct {
	result appcontracts.LoadResult
	err    error
}

func (m *mockObsRepo) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return m.result, m.err
}

type mockCtlRepo struct {
	controls []policy.ControlDefinition
	err      error
}

func (m *mockCtlRepo) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return m.controls, m.err
}

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

func baseTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func simpleSnapshots() []asset.Snapshot {
	base := baseTime()
	return []asset.Snapshot{
		{
			CapturedAt: base,
			Assets:     []asset.Asset{{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}},
		},
		{
			CapturedAt: base.Add(time.Hour),
			Assets:     []asset.Asset{{ID: "bucket-1", Type: kernel.AssetType("s3_bucket")}},
		},
	}
}

func simpleControls() []policy.ControlDefinition {
	ctl := policy.ControlDefinition{
		ID:   kernel.ControlID("CTL.TEST.001"),
		Name: "test",
		Type: policy.TypeUnsafeDuration,
	}
	_ = ctl.Prepare()
	return []policy.ControlDefinition{ctl}
}

func celEvalAllSafe() policy.PredicateEval {
	return func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}
}

// ---------------------------------------------------------------------------
// NewRun
// ---------------------------------------------------------------------------

func TestNewRun_NilObs(t *testing.T) {
	_, err := NewRun(nil, &mockCtlRepo{})
	if err == nil {
		t.Fatal("expected error for nil ObservationRepository")
	}
}

func TestNewRun_NilCtl(t *testing.T) {
	_, err := NewRun(&mockObsRepo{}, nil)
	if err == nil {
		t.Fatal("expected error for nil ControlRepository")
	}
}

func TestNewRun_Success(t *testing.T) {
	run, err := NewRun(&mockObsRepo{}, &mockCtlRepo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if run == nil {
		t.Fatal("expected non-nil Run")
	}
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

func TestExecute_ControlLoadError(t *testing.T) {
	run := &Run{
		ObservationRepo: &mockObsRepo{result: appcontracts.LoadResult{Snapshots: simpleSnapshots()}},
		ControlRepo:     &mockCtlRepo{err: errors.New("controls broken")},
	}

	_, err := run.Execute(context.Background(), Config{
		ControlsDir:     "controls",
		ObservationsDir: "observations",
		Clock:           ports.FixedClock(baseTime()),
	})
	if err == nil {
		t.Fatal("expected error for control load failure")
	}
}

func TestExecute_ObservationLoadError(t *testing.T) {
	run := &Run{
		ObservationRepo: &mockObsRepo{err: errors.New("obs broken")},
		ControlRepo:     &mockCtlRepo{controls: simpleControls()},
	}

	_, err := run.Execute(context.Background(), Config{
		ControlsDir:     "controls",
		ObservationsDir: "observations",
		Clock:           ports.FixedClock(baseTime()),
	})
	if err == nil {
		t.Fatal("expected error for observation load failure")
	}
}

func TestExecute_WithPreviousResult(t *testing.T) {
	run := &Run{
		ObservationRepo: &mockObsRepo{result: appcontracts.LoadResult{Snapshots: simpleSnapshots()}},
		ControlRepo:     &mockCtlRepo{controls: simpleControls()},
	}

	prev := &evaluation.Result{
		Findings: []evaluation.Finding{
			{ControlID: "CTL.TEST.001", AssetID: "bucket-1"},
		},
		Summary: evaluation.Summary{Violations: 1},
	}

	report, err := run.Execute(context.Background(), Config{
		ControlsDir:     "controls",
		ObservationsDir: "observations",
		Clock:           ports.FixedClock(baseTime().Add(2 * time.Hour)),
		PreviousResult:  prev,
		PredicateEval:   celEvalAllSafe(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
}

func TestExecute_FreshEvaluation(t *testing.T) {
	run := &Run{
		ObservationRepo: &mockObsRepo{result: appcontracts.LoadResult{Snapshots: simpleSnapshots()}},
		ControlRepo:     &mockCtlRepo{controls: simpleControls()},
	}

	report, err := run.Execute(context.Background(), Config{
		ControlsDir:       "controls",
		ObservationsDir:   "observations",
		MaxUnsafeDuration: 168 * time.Hour,
		Clock:             ports.FixedClock(baseTime().Add(2 * time.Hour)),
		PredicateEval:     celEvalAllSafe(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("expected non-nil report")
	}
}

// ---------------------------------------------------------------------------
// ExecuteFindingDetail
// ---------------------------------------------------------------------------

func TestExecuteFindingDetail_LoadError(t *testing.T) {
	run := &Run{
		ObservationRepo: &mockObsRepo{err: errors.New("broken")},
		ControlRepo:     &mockCtlRepo{controls: simpleControls()},
	}

	_, err := run.ExecuteFindingDetail(context.Background(), FindingDetailConfig{
		DiagnoseConfig: Config{
			ControlsDir:     "controls",
			ObservationsDir: "observations",
			Clock:           ports.FixedClock(baseTime()),
		},
		ControlID: "CTL.TEST.001",
		AssetID:   "bucket-1",
	})
	if err == nil {
		t.Fatal("expected error for load failure")
	}
}

// ---------------------------------------------------------------------------
// toDiagnosticFindings
// ---------------------------------------------------------------------------

func TestToDiagnosticFindings_FieldMapping(t *testing.T) {
	base := baseTime()
	findings := []evaluation.Finding{
		{
			ControlID: "CTL.A.001",
			AssetID:   "bucket-1",
			Evidence: evaluation.Evidence{
				FirstUnsafeAt:       base,
				LastSeenUnsafeAt:    base.Add(time.Hour),
				UnsafeDurationHours: 1.0,
				ThresholdHours:      0.5,
			},
		},
	}

	result := toDiagnosticFindings(findings)
	if len(result) != 1 {
		t.Fatalf("expected 1 diagnostic finding, got %d", len(result))
	}
	if result[0].ControlID != "CTL.A.001" {
		t.Fatalf("ControlID = %v", result[0].ControlID)
	}
	if result[0].ThresholdHours != 0.5 {
		t.Fatalf("ThresholdHours = %v", result[0].ThresholdHours)
	}
}

func TestToDiagnosticFindings_Empty(t *testing.T) {
	result := toDiagnosticFindings(nil)
	if len(result) != 0 {
		t.Fatalf("expected 0, got %d", len(result))
	}
}
