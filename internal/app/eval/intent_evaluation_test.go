package eval

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestIntentEvaluationLoadArtifacts_LoadsBoth(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	controls := []policy.ControlDefinition{{
		ID:          "CTL.TEST.001",
		Name:        "test",
		Description: "test",
		Type:        policy.TypeUnsafeState,
	}}
	snapshots := []asset.Snapshot{{
		CapturedAt:  now,
		GeneratedBy: &asset.GeneratedBy{SourceType: kernel.SourceTypeTerraformPlanJSON},
	}}

	intent := NewIntentEvaluation(
		evalObservationRepoStub{snapshots: snapshots},
		evalControlRepoStub{controls: controls},
	)

	result := intent.LoadArtifacts(context.Background(), IntentEvaluationConfig{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
		RequireControls: true,
	})

	if result.HasErrors() {
		t.Fatalf("expected no errors, got ctl=%v obs=%v", result.ControlErr, result.ObservationErr)
	}
	if len(result.Controls) != 1 {
		t.Fatalf("controls=%d, want 1", len(result.Controls))
	}
	if len(result.Snapshots) != 1 {
		t.Fatalf("snapshots=%d, want 1", len(result.Snapshots))
	}
}

func TestIntentEvaluationLoadArtifacts_CollectsBothErrors(t *testing.T) {
	intent := NewIntentEvaluation(
		evalObservationRepoStub{err: errors.New("obs boom")},
		evalControlRepoStub{err: errors.New("ctl boom")},
	)
	result := intent.LoadArtifacts(context.Background(), IntentEvaluationConfig{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
	})

	if result.ControlErr == nil || !strings.Contains(result.ControlErr.Error(), "failed to load controls") {
		t.Fatalf("unexpected control error: %v", result.ControlErr)
	}
	if result.ObservationErr == nil || !strings.Contains(result.ObservationErr.Error(), "failed to load observations") {
		t.Fatalf("unexpected observation error: %v", result.ObservationErr)
	}
}

func TestIntentEvaluationLoadArtifacts_SourceTypeCheckOptional(t *testing.T) {
	snapshots := []asset.Snapshot{{}}
	intent := NewIntentEvaluation(
		evalObservationRepoStub{snapshots: snapshots},
		evalControlRepoStub{controls: []policy.ControlDefinition{{ID: "CTL.TEST.001"}}},
	)

	result := intent.LoadArtifacts(context.Background(), IntentEvaluationConfig{
		ControlsDir:         "ctl",
		ObservationsDir:     "obs",
		OptionalSnapshots:   true,
		SkipSourceTypeCheck: true,
	})
	if result.ObservationErr != nil {
		t.Fatalf("expected no observation compatibility error when check disabled, got: %v", result.ObservationErr)
	}

	result = intent.LoadArtifacts(context.Background(), IntentEvaluationConfig{
		ControlsDir:       "ctl",
		ObservationsDir:   "obs",
		OptionalSnapshots: true,
	})
	if result.ObservationErr == nil || !errors.Is(result.ObservationErr, ErrSourceTypeMissing) {
		t.Fatalf("expected source_type compatibility error, got: %v", result.ObservationErr)
	}
}

func TestIntentEvaluationLoadArtifacts_RequireArtifacts(t *testing.T) {
	intent := NewIntentEvaluation(evalObservationRepoStub{}, evalControlRepoStub{})
	result := intent.LoadArtifacts(context.Background(), IntentEvaluationConfig{
		ControlsDir:     "ctl",
		ObservationsDir: "obs",
		RequireControls: true,
	})
	if result.ControlErr == nil || !errors.Is(result.ControlErr, ErrNoControls) {
		t.Fatalf("expected required control error, got: %v", result.ControlErr)
	}
	if result.ObservationErr == nil || !errors.Is(result.ObservationErr, ErrNoSnapshots) {
		t.Fatalf("expected required snapshot error, got: %v", result.ObservationErr)
	}
}
