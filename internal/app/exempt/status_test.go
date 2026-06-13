package exempt

import (
	"testing"
	"time"
)

func TestComputeStatus_ExpiringExemption(t *testing.T) {
	now, _ := time.Parse("2006-01-02", "2026-04-01")
	file := &AcceptanceFile{
		Acknowledgments: []AcknowledgmentEntry{
			{ControlID: "CTL.A.001", AssetID: "asset-1",
				ExpiryDate: "2026-04-15", Status: "active", Reason: "migration"},
		},
	}

	report := ComputeStatus(file, now, nil)
	if report.ExpiringDays30 != 1 {
		t.Errorf("expiring 30d = %d, want 1", report.ExpiringDays30)
	}
}

func TestComputeStatus_ExpiredNotRevoked(t *testing.T) {
	now, _ := time.Parse("2006-01-02", "2026-04-01")
	file := &AcceptanceFile{
		Acknowledgments: []AcknowledgmentEntry{
			{ControlID: "CTL.A.001", AssetID: "asset-1",
				ExpiryDate: "2026-02-01", Status: "active", Reason: "old"},
		},
	}

	report := ComputeStatus(file, now, nil)
	if report.AlreadyExpired != 1 {
		t.Errorf("expired = %d, want 1", report.AlreadyExpired)
	}
}

func TestComputeStatus_ResolvedFinding(t *testing.T) {
	now, _ := time.Parse("2006-01-02", "2026-04-01")
	file := &AcceptanceFile{
		Acknowledgments: []AcknowledgmentEntry{
			{ControlID: "CTL.A.001", AssetID: "asset-1",
				ExpiryDate: "2027-01-01", Status: "active", AcknowledgedDate: "2025-10-01"},
		},
	}
	// Finding no longer active.
	activeFindings := map[string]struct{}{}

	report := ComputeStatus(file, now, activeFindings)
	if report.Resolved != 1 {
		t.Errorf("resolved = %d, want 1", report.Resolved)
	}
}
