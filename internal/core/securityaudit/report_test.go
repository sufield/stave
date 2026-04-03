package securityaudit

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/outcome"
)

func TestReportFilterBySeverity(t *testing.T) {
	report := Report{
		Summary: Summary{FailOn: policy.SeverityHigh},
		Findings: []Finding{
			{ID: "A", Severity: policy.SeverityCritical, Status: outcome.Fail},
			{ID: "B", Severity: policy.SeverityMedium, Status: outcome.Warn},
			{ID: "C", Severity: policy.SeverityLow, Status: outcome.Pass},
		},
	}
	filtered := report.CloneWithFilter([]policy.Severity{policy.SeverityCritical, policy.SeverityHigh})
	if len(filtered.Findings) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(filtered.Findings))
	}
	if filtered.Findings[0].ID != "A" {
		t.Fatalf("unexpected finding kept: %s", filtered.Findings[0].ID)
	}
}

func TestSeverityGte(t *testing.T) {
	if !policy.SeverityCritical.Gte(policy.SeverityHigh) {
		t.Fatal("critical should be at or above high")
	}
	if policy.SeverityLow.Gte(policy.SeverityHigh) {
		t.Fatal("low should not be at or above high")
	}
	if !policy.SeverityCritical.Gte(policy.SeverityNone) {
		t.Fatal("every severity should be >= none")
	}
	if !policy.SeverityNone.Gte(policy.SeverityNone) {
		t.Fatal("none should be >= none")
	}
}
