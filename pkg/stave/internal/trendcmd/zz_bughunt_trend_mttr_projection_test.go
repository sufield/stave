package trendcmd

import (
	"testing"
	"time"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_BuildMTTRHistory_Alignment(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	t4 := time.Date(2026, 1, 4, 0, 0, 0, 0, time.UTC)
	t5 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	t6 := time.Date(2026, 1, 6, 0, 0, 0, 0, time.UTC)
	t7 := time.Date(2026, 1, 7, 0, 0, 0, 0, time.UTC)
	t8 := time.Date(2026, 1, 8, 0, 0, 0, 0, time.UTC)

	assessments := []*report.Assessment{
		makeAssessment(t1, []evaluation.Finding{
			finding("CTL.1", "res1", policy.SeverityCritical),
			finding("CTL.2", "res2", policy.SeverityCritical),
		}, 10, 2),
		makeAssessment(t2, []evaluation.Finding{
			finding("CTL.2", "res2", policy.SeverityCritical), // CTL.1 resolved (duration 24h)
		}, 10, 1),
		makeAssessment(t3, []evaluation.Finding{
			finding("CTL.2", "res2", policy.SeverityCritical),
		}, 10, 1),
		makeAssessment(t4, []evaluation.Finding{}, 10, 0), // CTL.2 resolved (duration 72h)
		makeAssessment(t5, []evaluation.Finding{}, 10, 0),
		makeAssessment(t6, []evaluation.Finding{}, 10, 0),
		makeAssessment(t7, []evaluation.Finding{}, 10, 0),
		makeAssessment(t8, []evaluation.Finding{}, 10, 0),
	}

	mttrHistory := buildMTTRHistory(assessments)

	// Since we passed 8 assessments representing a chronological time series,
	// the returned MTTR history for critical severity should align with these 8 points
	// so that index i corresponds to the average MTTR at assessment i.
	//
	// Under the buggy code: it only appends resolved durations directly, resulting in
	// a slice of length 2 (representing the 2 resolved findings), which causes
	// a dimensional mismatch in linear regression forecasting.
	if len(mttrHistory[policy.SeverityCritical]) != len(assessments) {
		t.Fatalf("expected critical MTTR history length to be %d (one per assessment point), but got %d",
			len(assessments), len(mttrHistory[policy.SeverityCritical]))
	}
}
