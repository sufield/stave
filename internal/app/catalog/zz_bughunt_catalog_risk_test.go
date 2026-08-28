package catalog

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
)

func TestBugHunt_OrderEntries_SeverityRiskSort(t *testing.T) {
	// A collection of controls with varying severity
	controls := []policy.ControlDefinition{
		{ID: "CTL.1", Severity: policy.SeverityCritical}, // Rank 5
		{ID: "CTL.2", Severity: policy.SeverityMedium},   // Rank 3
		{ID: "CTL.3", Severity: policy.SeverityLow},      // Rank 2
		{ID: "CTL.4", Severity: policy.SeverityInfo},     // Rank 1
		{ID: "CTL.5", Severity: policy.SeverityHigh},     // Rank 4
	}

	entries := SummarizePolicies(controls)
	err := OrderEntries(entries, "risk")
	if err != nil {
		t.Fatalf("OrderEntries failed: %v", err)
	}

	// We expect descending order by severity rank: critical -> high -> medium -> low -> info
	expectedOrder := []policy.Severity{policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium, policy.SeverityLow, policy.SeverityInfo}
	for i, expected := range expectedOrder {
		if entries[i].Risk != expected {
			t.Errorf("At index %d: expected risk %v, got %v", i, expected, entries[i].Risk)
		}
	}
}
