package exempt

import (
	"testing"
	"time"
)

func TestBugHunt_ComputeStatus_Expiring60dListed(t *testing.T) {
	now, _ := time.Parse("2006-01-02", "2026-04-01")
	file := &AcceptanceFile{
		Acknowledgments: []AcknowledgmentEntry{
			{
				ControlID:   "CTL.A.001",
				AssetID:     "asset-1",
				ExpiryDate:  "2026-05-15", // 44 days after now (within 60d)
				Status:      "active",
				Reason:      "migration",
			},
		},
	}

	report := ComputeStatus(file, now, nil)

	if report.ExpiringDays60 != 1 {
		t.Fatalf("expected ExpiringDays60 to be 1, got %d", report.ExpiringDays60)
	}

	// Under the buggy code: ExpiringItems is empty because "expiring_60d" case does not append to ExpiringItems.
	// Under the correct code: ExpiringItems should list this item since it is expiring soon (within 60 days).
	if len(report.ExpiringItems) != 1 {
		t.Errorf("expected 1 item in ExpiringItems list for 60d expiry, got %d", len(report.ExpiringItems))
	}
}
