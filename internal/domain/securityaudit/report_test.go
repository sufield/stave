package securityaudit

import "testing"

func TestReportFilterBySeverity(t *testing.T) {
	report := Report{
		Summary: Summary{FailOn: SeverityHigh},
		Findings: []Finding{
			{ID: "A", Severity: SeverityCritical, Status: StatusFail},
			{ID: "B", Severity: SeverityMedium, Status: StatusWarn},
			{ID: "C", Severity: SeverityLow, Status: StatusPass},
		},
	}
	filtered := report.FilterBySeverity([]Severity{SeverityCritical, SeverityHigh})
	if len(filtered.Findings) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(filtered.Findings))
	}
	if filtered.Findings[0].ID != "A" {
		t.Fatalf("unexpected finding kept: %s", filtered.Findings[0].ID)
	}
}

func TestAtOrAbove(t *testing.T) {
	if !AtOrAbove(SeverityCritical, SeverityHigh) {
		t.Fatal("critical should be at or above high")
	}
	if AtOrAbove(SeverityLow, SeverityHigh) {
		t.Fatal("low should not be at or above high")
	}
	if AtOrAbove(SeverityCritical, SeverityNone) {
		t.Fatal("threshold none should never gate")
	}
}
