package trendpredict

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Predict_MTTRNotCappedByLookback(t *testing.T) {
	// EvalTime is Day 100. Lookback is 30 days (so cutoff is Day 70).
	// Assessment 1: Day 0 (100 days ago) -> Finding present.
	// Assessment 2: Day 70 (30 days ago) -> Finding present.
	// Assessment 3: Day 80 (20 days ago) -> Finding resolved.
	// Assessment 4: Day 100 (today) -> Still resolved.
	// Actual MTTR for this finding should be 80 days.
	// Under the buggy code: Assessment 1 is skipped because Day 0 < Day 70.
	// So it only sees it first at Day 70, making the computed MTTR 10 days.

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t70 := t0.AddDate(0, 0, 70)
	t80 := t0.AddDate(0, 0, 80)
	t100 := t0.AddDate(0, 0, 100)

	history := []*report.Assessment{
		{
			Run:      evaluation.RunInfo{EvalTime: t0},
			Findings: []remediation.Finding{{ControlID: "CTL.A", AssetID: "asset-1", ControlSeverity: policy.SeverityHigh}},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t70},
			Findings: []remediation.Finding{{ControlID: "CTL.A", AssetID: "asset-1", ControlSeverity: policy.SeverityHigh}},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t80},
			Findings: []remediation.Finding{},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t100},
			Findings: []remediation.Finding{},
		},
	}

	res := computeMTTR(history, 30*24*time.Hour, t100)

	// We expect the high severity MTTR to be 80 days.
	// Under the buggy code, it will be 10 days.
	got, ok := res[policy.SeverityHigh]
	if !ok {
		t.Fatalf("expected high severity MTTR to be computed")
	}
	if got != 80.0 {
		t.Fatalf("expected MTTR to be 80.0 days, got %v", got)
	}
}
