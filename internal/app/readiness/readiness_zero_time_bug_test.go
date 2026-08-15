package readiness

import (
	"testing"
	"time"

	validation "github.com/sufield/stave/internal/core/schemaval"
)

func TestAssessReadiness_ZeroCurrentTimeDefaultedToNow(t *testing.T) {
	var capturedEvalTime time.Time

	ctx := validation.AssessmentContext{
		CurrentTime: time.Time{}, // zero CurrentTime
		RunEvaluation: func(dur time.Duration, evalTime time.Time) (validation.EvaluationState, error) {
			capturedEvalTime = evalTime
			return validation.EvaluationState{}, nil
		},
	}

	_, err := AssessReadiness(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedEvalTime.IsZero() {
		t.Errorf("expected non-zero evalTime passed to RunEvaluation when CurrentTime is zero")
	}
}
