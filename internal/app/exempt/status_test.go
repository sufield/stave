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

func TestExpiryAndResolvedItems_DomainMethods(t *testing.T) {
	expiring := ExpiryItems{
		{ControlID: "CTL.A.001", AssetID: "asset-1"},
		{ControlID: "CTL.B.002", AssetID: "asset-2"},
	}
	if expiring.Len() != 2 {
		t.Errorf("expiring.Len() = %d, want 2", expiring.Len())
	}
	if expiring.ByControl("CTL.A.001").Len() != 1 {
		t.Errorf("ByControl(CTL.A.001) = %d, want 1", expiring.ByControl("CTL.A.001").Len())
	}

	var emptyExpiring ExpiryItems
	if emptyExpiring.Len() != 0 || emptyExpiring.ByControl("CTL.A.001") != nil {
		t.Errorf("emptyExpiring methods failed")
	}

	resolved := ResolvedItems{
		{ControlID: "CTL.A.001", AssetID: "asset-1"},
	}
	if resolved.Len() != 1 {
		t.Errorf("resolved.Len() = %d, want 1", resolved.Len())
	}
	if resolved.ByControl("CTL.A.001").Len() != 1 {
		t.Errorf("resolved.ByControl(CTL.A.001) = %d, want 1", resolved.ByControl("CTL.A.001").Len())
	}

	var emptyResolved ResolvedItems
	if emptyResolved.Len() != 0 || emptyResolved.ByControl("CTL.A.001") != nil {
		t.Errorf("emptyResolved methods failed")
	}
}
