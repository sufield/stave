package trendpredict

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/report"
)

func TestPredict_NilAssessmentsHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Predict panicked on nil assessment entry: %v", rec)
		}
	}()

	in := Input{
		Assessments:     []*report.Assessment{nil},
		Profile:         "cis_aws",
		TargetReadiness: 100,
		EvalTime:        time.Now(),
	}

	pred := Predict(in)
	if pred == nil {
		t.Fatalf("expected non-nil prediction")
	}
}
