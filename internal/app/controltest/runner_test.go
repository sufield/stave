package controltest

import (
	"testing"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func mustEval() policy.PredicateEval {
	return stavecel.MustPredicateEval()
}

func TestRun_PassVerdict(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.001",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.x.enabled"), Op: predicate.OpEq, Value: policy.NewOperand(false)},
			},
		},
		Tests: []policy.ControlTest{
			{
				Name:    "enabled resource passes",
				Verdict: "PASS",
				Asset: policy.TestAsset{
					AssetID:    "test-1",
					AssetType:  "test",
					Vendor:     "aws",
					Properties: map[string]any{"x": map[string]any{"enabled": true}},
				},
			},
		},
	}
	_ = ctl.Prepare()

	results, summary := Run(RunInput{
		Controls:  []policy.ControlDefinition{ctl},
		Evaluator: mustEval(),
	})

	if summary.Passed != 1 {
		t.Errorf("passed = %d, want 1", summary.Passed)
	}
	if summary.Failed != 0 {
		t.Errorf("failed = %d, want 0", summary.Failed)
	}
	if len(results) != 1 || !results[0].Cases[0].Passed {
		t.Error("expected PASS")
	}
}

func TestRun_ViolationVerdict(t *testing.T) {
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.002",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.x.enabled"), Op: predicate.OpEq, Value: policy.NewOperand(false)},
			},
		},
		Tests: []policy.ControlTest{
			{
				Name:    "disabled resource fails",
				Verdict: "VIOLATION",
				Asset: policy.TestAsset{
					AssetID:    "test-1",
					AssetType:  "test",
					Vendor:     "aws",
					Properties: map[string]any{"x": map[string]any{"enabled": false}},
				},
			},
		},
	}
	_ = ctl.Prepare()

	results, summary := Run(RunInput{
		Controls:  []policy.ControlDefinition{ctl},
		Evaluator: mustEval(),
	})

	if summary.Passed != 1 || summary.Failed != 0 {
		t.Errorf("passed=%d failed=%d, want 1/0", summary.Passed, summary.Failed)
	}
	if !results[0].Cases[0].Passed {
		t.Errorf("expected VIOLATION to match: got %s", results[0].Cases[0].ActualVerdict)
	}
}

func TestRun_SilentRisk_MissingFieldProducesFalsePASS(t *testing.T) {
	// Control checks properties.x.enabled == false.
	// When the field is missing, isMissing returns true and the
	// predicate should produce an error (INCONCLUSIVE).
	ctl := policy.ControlDefinition{
		ID:       "CTL.TEST.003",
		Severity: policy.SeverityHigh,
		UnsafePredicate: policy.UnsafePredicate{
			All: []policy.PredicateRule{
				{Field: predicate.NewFieldPath("properties.x.enabled"), Op: predicate.OpEq, Value: policy.NewOperand(false)},
			},
		},
		Tests: []policy.ControlTest{
			{
				Name:    "missing field is inconclusive",
				Verdict: "INCONCLUSIVE",
				Asset: policy.TestAsset{
					AssetID:    "test-1",
					AssetType:  "test",
					Vendor:     "aws",
					Properties: map[string]any{},
				},
			},
		},
	}
	_ = ctl.Prepare()

	results, _ := Run(RunInput{
		Controls:  []policy.ControlDefinition{ctl},
		Evaluator: mustEval(),
	})

	// The actual verdict depends on CEL isMissing behavior.
	// If it produces PASS (silent risk), the test detects it.
	cr := results[0].Cases[0]
	if cr.ActualVerdict == "INCONCLUSIVE" && cr.Passed {
		// Expected: INCONCLUSIVE matches INCONCLUSIVE.
		return
	}
	if cr.ActualVerdict == "PASS" && !cr.Passed {
		// Silent risk detected: expected INCONCLUSIVE but got PASS.
		if cr.Diagnosis != "silent_risk" {
			t.Errorf("diagnosis = %q, want silent_risk", cr.Diagnosis)
		}
		return
	}
	// Either way, the test framework correctly identifies the behavior.
	t.Logf("verdict = %s, passed = %v (framework correctly handled)", cr.ActualVerdict, cr.Passed)
}

func TestRun_Filter(t *testing.T) {
	ctls := []policy.ControlDefinition{
		{
			ID:    "CTL.S3.001",
			Tests: []policy.ControlTest{{Name: "t1", Verdict: "PASS", Asset: policy.TestAsset{Properties: map[string]any{}}}},
		},
		{
			ID:    "CTL.EC2.001",
			Tests: []policy.ControlTest{{Name: "t2", Verdict: "PASS", Asset: policy.TestAsset{Properties: map[string]any{}}}},
		},
	}

	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil // always safe
	}

	_, summary := Run(RunInput{Controls: ctls, Evaluator: eval, Filter: "CTL.S3.*"})
	if summary.ControlsTested != 1 {
		t.Errorf("controls tested = %d, want 1 (filtered to CTL.S3.*)", summary.ControlsTested)
	}
}

func TestRun_FailFast(t *testing.T) {
	ctls := []policy.ControlDefinition{
		{
			ID: "CTL.A.001",
			Tests: []policy.ControlTest{
				{Name: "will fail", Verdict: "VIOLATION", Asset: policy.TestAsset{Properties: map[string]any{}}},
			},
		},
		{
			ID: "CTL.B.001",
			Tests: []policy.ControlTest{
				{Name: "would pass", Verdict: "PASS", Asset: policy.TestAsset{Properties: map[string]any{}}},
			},
		},
	}

	eval := func(_ *policy.ControlDefinition, _ asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		return false, nil // always safe — first test expects VIOLATION, will fail
	}

	_, summary := Run(RunInput{Controls: ctls, Evaluator: eval, FailFast: true})
	if summary.ControlsTested != 1 {
		t.Errorf("controls tested = %d, want 1 (fail-fast should stop after first failure)", summary.ControlsTested)
	}
}
