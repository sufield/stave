package findingfilter

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_FindingFilter_FirstSeenGapCount(t *testing.T) {
	// t0: absent
	// t1: absent
	// t2: present (first seen in history, idx = 2)
	// t3: absent (latest historical)
	hist := []*report.Assessment{
		assessment(t0),
		assessment(t1),
		assessment(t2, finding("CTL.A.001", "asset1")),
		assessment(t3),
	}

	// Current assessment at t4 contains the finding again (reappeared).
	t4 := time.Date(2026, 3, 29, 0, 0, 0, 0, time.UTC)
	current := []remediation.Finding{
		finding("CTL.A.001", "asset1"),
	}

	result := Classify(Input{
		CurrentFindings: current,
		History:         hist,
		EvalTime:        t4,
	})

	if len(result.ReturnedFindings) != 1 {
		t.Fatalf("expected 1 returned finding, got %d", len(result.ReturnedFindings))
	}

	// Since the finding was first seen at t2 and has never disappeared/reappeared
	// *within* the historical timeline, its gap count should be 0, and returned cycles should be 1.
	// Under the buggy code: gaps is incorrectly incremented at t2 because it's the first
	// time it is added, wasPresentPrev is false, wasPresentCurr is true, and idx >= 2.
	if got := result.ReturnedFindings[0].Cycles; got != 1 {
		t.Errorf("expected Cycles to be 1, got %d", got)
	}
}
