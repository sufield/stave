package diagnose

import (
	"testing"

	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
)

func TestFilter_Apply_NoFiltersReturnsOriginal(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Insight{
			{Case: diagnosis.ScenarioExpectedNone, Signal: "threshold too high"},
		},
	}
	filtered := Filter{}.Apply(report)
	if len(filtered.Issues) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(filtered.Issues))
	}
}

func TestFilter_Apply_ByCaseAndSignal(t *testing.T) {
	report := &diagnosis.Report{
		Issues: []diagnosis.Insight{
			{Case: diagnosis.ScenarioExpectedNone, Signal: "threshold too high"},
			{Case: diagnosis.ScenarioEmptyFindings, Signal: "no predicate matches"},
			{Case: diagnosis.ScenarioViolationEvidence, Signal: "streak evidence available"},
		},
	}
	filtered := Filter{
		Cases:          []string{string(diagnosis.ScenarioExpectedNone), string(diagnosis.ScenarioEmptyFindings)},
		SignalContains: "threshold",
	}.Apply(report)
	if len(filtered.Issues) != 1 {
		t.Fatalf("expected 1 diagnostic after filters, got %d", len(filtered.Issues))
	}
	if filtered.Issues[0].Case != diagnosis.ScenarioExpectedNone {
		t.Fatalf("unexpected case after filtering: %s", filtered.Issues[0].Case)
	}
}

func TestFilter_Apply_NilReport(t *testing.T) {
	result := Filter{Cases: []string{"x"}}.Apply(nil)
	if result != nil {
		t.Fatal("expected nil for nil report")
	}
}

func TestFilter_IsEmpty(t *testing.T) {
	if !(Filter{}).IsEmpty() {
		t.Fatal("empty filter should be empty")
	}
	if (Filter{Cases: []string{"x"}}).IsEmpty() {
		t.Fatal("filter with cases should not be empty")
	}
	if (Filter{SignalContains: "y"}).IsEmpty() {
		t.Fatal("filter with signal should not be empty")
	}
}
