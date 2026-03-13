package diagnose

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
)

func TestFilterReport_NoFiltersReturnsOriginal(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: diagnosis.ScenarioExpectedNone, Signal: "threshold too high"},
		},
	}
	filtered := FilterReport(report, Filter{})
	if len(filtered.Issues) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(filtered.Issues))
	}
}

func TestFilterReport_ByCaseAndSignal(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{Case: diagnosis.ScenarioExpectedNone, Signal: "threshold too high"},
			{Case: diagnosis.ScenarioEmptyFindings, Signal: "no predicate matches"},
			{Case: diagnosis.ScenarioViolationEvidence, Signal: "streak evidence available"},
		},
	}
	filtered := FilterReport(report, Filter{
		Cases:          []string{string(diagnosis.ScenarioExpectedNone), string(diagnosis.ScenarioEmptyFindings)},
		SignalContains: "threshold",
	})
	if len(filtered.Issues) != 1 {
		t.Fatalf("expected 1 diagnostic after filters, got %d", len(filtered.Issues))
	}
	if filtered.Issues[0].Case != diagnosis.ScenarioExpectedNone {
		t.Fatalf("unexpected case after filtering: %s", filtered.Issues[0].Case)
	}
}
