package controltest

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestBugHunt_Run_MixedCaseVerdictDiagnosis(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.001",
		Severity: policy.SeverityHigh,
		Tests: []policy.ControlTest{
			{
				Name:    "mixed case expected verdict",
				Verdict: "Pass", // mixed-case expected verdict
				Asset: policy.TestAsset{
					AssetID:   "test-1",
					AssetType: "test",
					Vendor:    "aws",
				},
			},
		},
	}

	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return true, nil // evaluates to VIOLATION (unsafe)
	}

	results, _ := Run(RunInput{
		Controls:  []policy.ControlDefinition{ctl},
		Evaluator: eval,
	})

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	cr := results[0].Cases[0]
	if cr.Passed {
		t.Fatal("expected test to fail")
	}

	// Under buggy code, ExpectedVerdict is "Pass". So expected == "PASS" is false.
	// This results in diagnosis = "unknown" instead of "predicate_logic_error".
	if cr.Diagnosis == "unknown" {
		t.Error("expected diagnosis to be 'predicate_logic_error', but was 'unknown'")
	}
	if cr.Diagnosis != "predicate_logic_error" {
		t.Errorf("expected diagnosis 'predicate_logic_error', got %q", cr.Diagnosis)
	}
}
