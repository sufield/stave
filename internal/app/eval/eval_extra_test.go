package eval

import (
	"errors"
	"testing"
)

func TestNewConfigBasic(t *testing.T) {
	plan := EvaluationPlan{
		ControlsPath:     "/controls",
		ObservationsPath: "/obs",
		ContextName:      "test",
	}
	cfg := NewConfig(plan)
	if cfg.PolicySource != "/controls" {
		t.Fatalf("PolicySource = %q", cfg.PolicySource)
	}
	if cfg.Metadata.ContextName != "test" {
		t.Fatalf("ContextName = %q", cfg.Metadata.ContextName)
	}
}

func TestNewConfigWithNilOptions(t *testing.T) {
	plan := EvaluationPlan{ControlsPath: "/c", ObservationsPath: "/o"}
	cfg := NewConfig(plan, nil, nil)
	if cfg.PolicySource != "/c" {
		t.Fatalf("PolicySource = %q", cfg.PolicySource)
	}
}

func TestIntentEvaluationResult_HasErrors(t *testing.T) {
	r := IntentEvaluationResult{}
	if r.HasErrors() {
		t.Fatal("empty result should not have errors")
	}

	r.ControlErr = errors.New("control error")
	if !r.HasErrors() {
		t.Fatal("should have errors with ControlErr set")
	}

	r = IntentEvaluationResult{ObservationErr: errors.New("obs error")}
	if !r.HasErrors() {
		t.Fatal("should have errors with ObservationErr set")
	}
}

func TestIntentEvaluationResult_FirstError(t *testing.T) {
	r := IntentEvaluationResult{}
	if r.FirstError() != nil {
		t.Fatal("empty result should return nil")
	}

	r = IntentEvaluationResult{ControlErr: errors.New("control only")}
	if r.FirstError().Error() != "control only" {
		t.Fatal("control-only path should return control error")
	}
	r = IntentEvaluationResult{ObservationErr: errors.New("obs only")}
	if r.FirstError().Error() != "obs only" {
		t.Fatal("observation-only path should return observation error")
	}

	ctlErr := errors.New("control error")
	obsErr := errors.New("obs error")
	r = IntentEvaluationResult{ControlErr: ctlErr, ObservationErr: obsErr}
	got := r.FirstError()
	if got == nil {
		t.Fatal("joined errors should yield non-nil")
	}
	if !errors.Is(got, ctlErr) {
		t.Errorf("joined error must wrap ControlErr; got %v", got)
	}
	if !errors.Is(got, obsErr) {
		t.Errorf("joined error must wrap ObservationErr; got %v", got)
	}
}
