package exemptionsuggest

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Suggest_DwellTimeNotCappedByWindow(t *testing.T) {
	// Let's set up history spanning 100 days.
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)  // 100 days ago
	t1 := time.Date(2026, 3, 11, 0, 0, 0, 0, time.UTC) // 30 days ago
	t2 := time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC) // today

	history := []*report.Assessment{
		{
			Run:      evaluation.RunInfo{EvalTime: t0},
			Findings: []remediation.Finding{{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "asset-1"}}},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t1},
			Findings: []remediation.Finding{{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "asset-1"}}},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t2},
			Findings: []remediation.Finding{{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "asset-1"}}},
		},
	}

	// Window is 30 days (so t0 is filtered out for oscillation analysis, but should not cap chronic dwell time)
	// MinDwell is 45 days.
	// Since CTL.A was first seen 100 days ago (t0) and is still present at t2, its dwell days is 100 days.
	// 100 days >= 45 days, so it should be suggested as chronic.
	// Under the buggy code: it filters assessments older than 30 days first, so t0 is discarded.
	// This caps the computed dwellDays at 30 days, which is less than MinDwell (45 days), so it returns 0 suggestions.
	result := Suggest(Input{
		History:  history,
		Window:   30 * 24 * time.Hour,
		MinDwell: 45 * 24 * time.Hour,
		EvalTime: t2,
	})

	if len(result.Chronic) != 1 {
		t.Fatalf("expected 1 chronic candidate (dwell time 100 days >= 45 days threshold), got %d", len(result.Chronic))
	}
}

func TestBugHunt_Suggest_DwellTimeResetOnSafe(t *testing.T) {
	// Day 0: Finding is present.
	// Day 50: Finding is absent (passed/fixed).
	// Day 90: Finding is present again (reopened).
	// Day 100: Evaluation time.
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(50 * 24 * time.Hour)
	t2 := t0.Add(90 * 24 * time.Hour)
	t3 := t0.Add(100 * 24 * time.Hour)

	history := []*report.Assessment{
		{
			Run:      evaluation.RunInfo{EvalTime: t0},
			Findings: []remediation.Finding{{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "asset-1"}}},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t1},
			Findings: []remediation.Finding{}, // passed!
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t2},
			Findings: []remediation.Finding{{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "asset-1"}}},
		},
		{
			Run:      evaluation.RunInfo{EvalTime: t3},
			Findings: []remediation.Finding{{Finding: evaluation.Finding{ControlID: "CTL.A", AssetID: "asset-1"}}},
		},
	}

	// MinDwell is 30 days.
	// The current active streak started at t2 (Day 90) and evaluation is at t3 (Day 100).
	// Current dwell time is 10 days.
	// 10 days < 30 days MinDwell, so it should NOT be suggested as chronic.
	// (Under buggy code: firstSeen remains t0, so dwell time = 100 days >= 30 days, incorrectly suggesting it as chronic).
	result := Suggest(Input{
		History:  history,
		Window:   120 * 24 * time.Hour,
		MinDwell: 30 * 24 * time.Hour,
		EvalTime: t3,
	})

	for _, c := range result.Chronic {
		if c.ControlID == "CTL.A" && c.AssetID == "asset-1" {
			t.Errorf("expected CTL.A@asset-1 NOT to be suggested as chronic since its current active streak is only 10 days, but got dwell days: %f", c.DwellDays)
		}
	}
}
