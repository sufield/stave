package report

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	corereport "github.com/sufield/stave/internal/core/report"
)

// TestAssessmentClosestTo_PicksWithinWindow asserts the helper picks
// the assessment whose timestamp is nearest the target instant — not
// the oldest in history. This is the load-bearing fix for the report
// 30-day trajectory: comparing against assessments[0] made the delta
// drift unboundedly with how long history had been accumulating.
func TestAssessmentClosestTo_PicksWithinWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)
	target := now.AddDate(0, 0, -30)

	mk := func(d time.Time) *corereport.Assessment {
		return &corereport.Assessment{Run: evaluation.RunInfo{Now: d}}
	}

	assessments := []*corereport.Assessment{
		mk(now.AddDate(0, -6, 0)),  // 6 months ago
		mk(now.AddDate(0, 0, -32)), // 2 days off the target
		mk(now.AddDate(0, 0, -29)), // 1 day off the target — winner
		mk(now.AddDate(0, 0, -7)),  // recent
		mk(now),                    // latest, excluded
	}

	got, ok := assessmentClosestTo(assessments, target)
	if !ok {
		t.Fatal("expected an assessment, got false")
	}
	want := assessments[2]
	if got != want {
		t.Errorf("got %v, want %v", got.Run.Now, want.Run.Now)
	}
}

// TestAssessmentClosestTo_FallbackOldest checks the fallback when no
// assessment lies near the target window: the helper still returns
// something so delta is meaningful even with sparse history. With
// exactly two entries the "earlier" entry is always chosen.
func TestAssessmentClosestTo_FallbackOldest(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)
	target := now.AddDate(0, 0, -30)

	mk := func(d time.Time) *corereport.Assessment {
		return &corereport.Assessment{Run: evaluation.RunInfo{Now: d}}
	}

	assessments := []*corereport.Assessment{
		mk(now.AddDate(-1, 0, 0)), // 1 year ago — only "earlier"
		mk(now),                   // latest, excluded
	}

	got, ok := assessmentClosestTo(assessments, target)
	if !ok {
		t.Fatal("expected an assessment")
	}
	if got != assessments[0] {
		t.Errorf("got %v, want oldest %v", got.Run.Now, assessments[0].Run.Now)
	}
}

// TestAssessmentClosestTo_SinglePointHistory pins delta=0 semantics
// for a single-data-point history: the helper returns false so the
// caller knows there is no earlier assessment to diff against.
func TestAssessmentClosestTo_SinglePointHistory(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)
	target := now.AddDate(0, 0, -30)

	assessments := []*corereport.Assessment{
		{Run: evaluation.RunInfo{Now: now}},
	}

	if _, ok := assessmentClosestTo(assessments, target); ok {
		t.Error("single-point history must report no earlier assessment")
	}
}
