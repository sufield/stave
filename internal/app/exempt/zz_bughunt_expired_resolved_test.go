package exempt

import (
	"testing"
	"time"
)

func TestBugHunt_Exempt_ExpiredButResolved(t *testing.T) {
	// Exemption is expired, but the finding is resolved (i.e. not in activeFindings)
	file := &AcceptanceFile{
		Acknowledgments: []AcknowledgmentEntry{
			{
				ControlID:        "CTL.S3.1",
				AssetID:          "arn:aws:s3:::bucket1",
				Status:           AckStatusActive,
				ExpiryDate:       "2026-03-01", // expired relative to now (2026-04-15)
				AcknowledgedDate: "2026-01-01",
				Reason:           "legacy",
			},
		},
	}

	now := time.Date(2026, 4, 15, 0, 0, 0, 0, time.UTC)
	// Finding is resolved, so it's not present in activeFindings map
	activeFindings := map[string]struct{}{}

	report := ComputeStatus(file, now, activeFindings)

	if report.AlreadyExpired != 1 {
		t.Errorf("expected AlreadyExpired = 1, got %d", report.AlreadyExpired)
	}

	// The finding is resolved, so we expect it to be flagged as resolved
	// even if the exemption is already expired.
	if report.Resolved != 1 {
		t.Errorf("expected Resolved = 1 for expired but resolved exemption, got %d", report.Resolved)
	}

	if len(report.ResolvedItems) != 1 {
		t.Fatalf("expected 1 ResolvedItem, got %d", len(report.ResolvedItems))
	}
}
