package trace

import "testing"

func TestComputeSummary_Empty(t *testing.T) {
	s := ComputeSummary(nil)
	if s.TotalAssessments != 0 {
		t.Errorf("total = %d, want 0", s.TotalAssessments)
	}
}

func TestComputeSummary_AllVerdicts(t *testing.T) {
	assessments := []Assessment{
		{Verdict: "VIOLATION"},
		{Verdict: "VIOLATION"},
		{Verdict: "PASS"},
		{Verdict: "PASS"},
		{Verdict: "PASS"},
		{Verdict: "SKIPPED"},
		{Verdict: "INCONCLUSIVE"},
		{Verdict: "NOT_APPLICABLE"},
	}
	s := ComputeSummary(assessments)
	if s.TotalAssessments != 8 {
		t.Errorf("total = %d, want 8", s.TotalAssessments)
	}
	if s.Violations != 2 {
		t.Errorf("violations = %d, want 2", s.Violations)
	}
	if s.Passes != 3 {
		t.Errorf("passes = %d, want 3", s.Passes)
	}
	if s.Skipped != 1 {
		t.Errorf("skipped = %d, want 1", s.Skipped)
	}
	if s.Inconclusive != 2 {
		t.Errorf("inconclusive = %d, want 2 (INCONCLUSIVE + NOT_APPLICABLE)", s.Inconclusive)
	}
}

func TestComputeSummary_UnknownVerdict(t *testing.T) {
	assessments := []Assessment{
		{Verdict: "UNKNOWN_THING"},
		{Verdict: "PASS"},
	}
	s := ComputeSummary(assessments)
	if s.TotalAssessments != 2 {
		t.Errorf("total = %d, want 2", s.TotalAssessments)
	}
	if s.Passes != 1 {
		t.Errorf("passes = %d, want 1", s.Passes)
	}
	if s.Violations+s.Skipped+s.Inconclusive != 0 {
		t.Errorf("unknown verdict should not increment any counter")
	}
}
