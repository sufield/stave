package controltest

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestRun_NilEvaluatorHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("Run panicked on nil Evaluator: %v", rec)
		}
	}()

	in := RunInput{
		Controls: []policy.ControlDefinition{
			{
				ID: kernel.ControlID("CTL.S3.001"),
				Tests: []policy.ControlTest{
					{
						Name:    "test case 1",
						Verdict: "PASS",
					},
				},
			},
		},
		Evaluator: nil, // nil evaluator
	}

	results, summary := Run(in)
	if summary.Failed != 1 {
		t.Errorf("expected 1 failed test case on nil evaluator, got %d", summary.Failed)
	}

	if len(results) != 1 || results[0].Cases[0].ActualVerdict != "INCONCLUSIVE" {
		t.Errorf("expected INCONCLUSIVE verdict for case on nil evaluator")
	}
}
