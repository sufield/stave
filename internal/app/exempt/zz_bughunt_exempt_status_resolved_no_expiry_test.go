package exempt

import (
	"testing"
	"time"
)

func TestBugHunt_ComputeStatus_ResolvedFinding_NoExpiryDate(t *testing.T) {
	now, _ := time.Parse("2006-01-02", "2026-04-01")
	file := &AcceptanceFile{
		Acknowledgments: []AcknowledgmentEntry{
			{
				ControlID:  "CTL.A.001",
				AssetID:    "asset-1",
				ExpiryDate: "", // No expiry date set
				Status:     "active",
				Reason:     "legacy exception",
			},
		},
	}

	// Finding is resolved (not in active findings map)
	activeFindings := map[string]struct{}{}

	report := ComputeStatus(file, now, activeFindings)
	if report.Resolved != 1 {
		t.Fatalf("expected resolved count to be 1, got %d (resolved check was bypassed)", report.Resolved)
	}
	if len(report.ResolvedItems) != 1 {
		t.Fatalf("expected 1 resolved item, got %d", len(report.ResolvedItems))
	}
}
