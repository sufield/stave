package diagnose

import (
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
)

func TestFilterDiagnosisReport_NoFiltersReturnsOriginal(t *testing.T) {
	report := &diagnosis.Report{
		Entries: []diagnosis.Entry{
			{Case: diagnosis.ExpectedNone, Signal: "threshold too high"},
		},
	}
	filtered := filterDiagnosisReport(report, nil, "")
	if len(filtered.Entries) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(filtered.Entries))
	}
}

func TestFilterDiagnosisReport_ByCaseAndSignal(t *testing.T) {
	report := &diagnosis.Report{
		Entries: []diagnosis.Entry{
			{Case: diagnosis.ExpectedNone, Signal: "threshold too high"},
			{Case: diagnosis.EmptyFindings, Signal: "no predicate matches"},
			{Case: diagnosis.ViolationEvidence, Signal: "streak evidence available"},
		},
	}
	filtered := filterDiagnosisReport(
		report,
		[]string{string(diagnosis.ExpectedNone), string(diagnosis.EmptyFindings)},
		"threshold",
	)
	if len(filtered.Entries) != 1 {
		t.Fatalf("expected 1 diagnostic after filters, got %d", len(filtered.Entries))
	}
	if filtered.Entries[0].Case != diagnosis.ExpectedNone {
		t.Fatalf("unexpected case after filtering: %s", filtered.Entries[0].Case)
	}
}
