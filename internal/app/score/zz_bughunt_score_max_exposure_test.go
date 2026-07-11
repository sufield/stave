package score

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestBugHunt_Score_MaxRiskExposureFallback(t *testing.T) {
	// A single High violation, TotalCheckWeight is 0 (triggering fallback).
	// ControlSeverity.NormalizedWeight() for High is 3.0.
	// SeverityCritical.NormalizedWeight() is 4.0.
	findings := []remediation.Finding{
		{Finding: evaluation.Finding{ControlSeverity: policy.SeverityHigh}},
	}

	r := Compute(Input{
		Findings: findings,
		Weights:  DefaultWeights(),
	})

	// Under fallback logic, the severity sub-score is calculated as:
	// 1.0 - (avgWeight / maxSev) = 1.0 - (3.0 / 4.0) = 0.25 (25%)
	// This means the effective denominator (maximum risk exposure) used for the scoring is 4.0.
	// But under the buggy code, MaxRiskExposure is reported as actualExposure (which is 3.0).
	// Reporting MaxRiskExposure = 3.0 alongside ActualExposure = 3.0 makes it look like
	// 100% of maximum risk was realized (which would mean a sub-score of 0%),
	// contradicting the actual 25% sub-score.
	expectedMax := float64(len(findings)) * policy.SeverityCritical.NormalizedWeight() // 4.0
	if got := r.Severity.Detail.MaxRiskExposure; got != expectedMax {
		t.Errorf("expected MaxRiskExposure to reflect the effective denominator %f, got %f", expectedMax, got)
	}
}
