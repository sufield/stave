package diagnose

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
)

func TestFilterDiagnosisReport_NoFiltersReturnsOriginal(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: diagnosis.ScenarioExpectedNone, Signal: "threshold too high"},
		},
	}
	filtered := filterDiagnosisReport(report, nil, "")
	if len(filtered.Issues) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(filtered.Issues))
	}
}

func TestFilterDiagnosisReport_ByCaseAndSignal(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: diagnosis.ScenarioExpectedNone, Signal: "threshold too high"},
			{Case: diagnosis.ScenarioEmptyFindings, Signal: "no predicate matches"},
			{Case: diagnosis.ScenarioViolationEvidence, Signal: "streak evidence available"},
		},
	}
	filtered := filterDiagnosisReport(
		report,
		[]string{string(diagnosis.ScenarioExpectedNone), string(diagnosis.ScenarioEmptyFindings)},
		"threshold",
	)
	if len(filtered.Issues) != 1 {
		t.Fatalf("expected 1 diagnostic after filters, got %d", len(filtered.Issues))
	}
	if filtered.Issues[0].Case != diagnosis.ScenarioExpectedNone {
		t.Fatalf("unexpected case after filtering: %s", filtered.Issues[0].Case)
	}
}
