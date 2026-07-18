package scorecard

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

func TestBugHunt_Compute_FrameworkSortDeterminism(t *testing.T) {
	// We pass empty findings so all frameworks have 0% readiness.
	// We pass frameworks in reverse alphabetical order: ["nist", "cis"].
	// Under buggy code, they are not sorted alphabetically because there is no tiebreaker,
	// so "nist" remains before "cis" or it is non-deterministic.
	// Under correct code, "cis" must come before "nist".
	frameworks := []string{"nist", "cis"}
	var findings []remediation.Finding

	report := Compute(findings, frameworks)
	if len(report.Frameworks) != 2 {
		t.Fatalf("expected 2 framework scores, got %d", len(report.Frameworks))
	}

	if report.Frameworks[0].Framework != "cis" {
		t.Errorf("expected CIS first (alphabetical tiebreaker), got %s", report.Frameworks[0].Framework)
	}
	if report.Frameworks[1].Framework != "nist" {
		t.Errorf("expected NIST second, got %s", report.Frameworks[1].Framework)
	}
}
