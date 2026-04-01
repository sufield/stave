package eval

import (
	"context"
	"errors"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// ---------------------------------------------------------------------------
// Mock ObservationRepository
// ---------------------------------------------------------------------------

type mockObsRepo struct {
	result appcontracts.LoadResult
	err    error
}

func (m *mockObsRepo) LoadSnapshots(_ context.Context, _ string) (appcontracts.LoadResult, error) {
	return m.result, m.err
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func testSnapshots(base time.Time) []asset.Snapshot {
	return []asset.Snapshot{
		{
			CapturedAt: base,
			Assets: []asset.Asset{{
				ID:         "bucket-1",
				Type:       kernel.AssetType("s3_bucket"),
				Properties: map[string]any{"public_access_block_enabled": true},
			}},
		},
		{
			CapturedAt: base.Add(time.Hour),
			Assets: []asset.Asset{{
				ID:         "bucket-1",
				Type:       kernel.AssetType("s3_bucket"),
				Properties: map[string]any{"public_access_block_enabled": true},
			}},
		},
	}
}

func testControls() []policy.ControlDefinition {
	ctl := policy.ControlDefinition{
		ID:   kernel.ControlID("CTL.TEST.001"),
		Name: "test control",
		Type: policy.TypeUnsafeDuration,
	}
	_ = ctl.Prepare()
	return []policy.ControlDefinition{ctl}
}

// ---------------------------------------------------------------------------
// RunDirectoryEvaluation
// ---------------------------------------------------------------------------

func TestRunDirectoryEvaluation_LoadError(t *testing.T) {
	repo := &mockObsRepo{err: errors.New("disk failure")}

	_, _, err := RunDirectoryEvaluation(DirectoryEvaluationRequest{
		Context:           context.Background(),
		ObservationsDir:   "/tmp/obs",
		ObservationLoader: repo,
	})
	if err == nil {
		t.Fatal("expected error for load failure")
	}
	if !containsString(err.Error(), "load observations") {
		t.Fatalf("expected 'load observations' in error, got: %v", err)
	}
}

func TestRunDirectoryEvaluation_EmptySnapshots(t *testing.T) {
	repo := &mockObsRepo{result: appcontracts.LoadResult{Snapshots: nil}}

	_, _, err := RunDirectoryEvaluation(DirectoryEvaluationRequest{
		Context:           context.Background(),
		ObservationsDir:   "/tmp/obs",
		ObservationLoader: repo,
	})
	if err == nil {
		t.Fatal("expected error for empty snapshots")
	}
	if !errors.Is(err, ErrNoSnapshots) {
		t.Fatalf("expected ErrNoSnapshots, got: %v", err)
	}
}

func TestRunDirectoryEvaluation_SourceTypeIncompatible(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := []asset.Snapshot{
		{
			CapturedAt:  base,
			Assets:      []asset.Asset{{ID: "b-1", Type: "s3_bucket"}},
			GeneratedBy: &asset.GeneratedBy{SourceType: "unknown_custom_tool"},
		},
	}
	repo := &mockObsRepo{result: appcontracts.LoadResult{Snapshots: snaps}}

	_, _, err := RunDirectoryEvaluation(DirectoryEvaluationRequest{
		Context:           context.Background(),
		ObservationsDir:   "/tmp/obs",
		Controls:          testControls(),
		ObservationLoader: repo,
		AllowUnknownType:  false,
	})
	if err == nil {
		t.Fatal("expected error for incompatible source type")
	}
	if !containsString(err.Error(), "source_type compatibility") {
		t.Fatalf("expected source_type error, got: %v", err)
	}
}

func TestRunDirectoryEvaluation_Success(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := &mockObsRepo{result: appcontracts.LoadResult{Snapshots: testSnapshots(base)}}

	celEval := func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil // all safe
	}

	result, snapCount, err := RunDirectoryEvaluation(DirectoryEvaluationRequest{
		Context:           context.Background(),
		ObservationsDir:   "/tmp/obs",
		Controls:          testControls(),
		MaxUnsafeDuration: 168 * time.Hour,
		Clock:             ports.FixedClock(base.Add(2 * time.Hour)),
		StaveVersion:      "test",
		ObservationLoader: repo,
		AllowUnknownType:  true,
		CELEvaluator:      celEval,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if snapCount != 2 {
		t.Fatalf("expected 2 snapshots, got %d", snapCount)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings (all safe), got %d", len(result.Findings))
	}
}

func TestRunDirectoryEvaluation_AllowUnknownType(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snaps := []asset.Snapshot{
		{
			CapturedAt:  base,
			Assets:      []asset.Asset{{ID: "b-1", Type: "s3_bucket"}},
			GeneratedBy: &asset.GeneratedBy{SourceType: "unknown_custom_tool"},
		},
		{
			CapturedAt:  base.Add(time.Hour),
			Assets:      []asset.Asset{{ID: "b-1", Type: "s3_bucket"}},
			GeneratedBy: &asset.GeneratedBy{SourceType: "unknown_custom_tool"},
		},
	}
	repo := &mockObsRepo{result: appcontracts.LoadResult{Snapshots: snaps}}

	celEval := func(_ policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil
	}

	result, _, err := RunDirectoryEvaluation(DirectoryEvaluationRequest{
		Context:           context.Background(),
		ObservationsDir:   "/tmp/obs",
		Controls:          testControls(),
		MaxUnsafeDuration: 168 * time.Hour,
		Clock:             ports.FixedClock(base.Add(2 * time.Hour)),
		StaveVersion:      "test",
		ObservationLoader: repo,
		AllowUnknownType:  true,
		CELEvaluator:      celEval,
	})
	if err != nil {
		t.Fatalf("--allow-unknown-input should bypass source type check: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
