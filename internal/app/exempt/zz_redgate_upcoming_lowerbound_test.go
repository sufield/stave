package exempt

import (
	"testing"
	"time"
)

// Test_RedGate_UpcomingLowerBound asserts the CORRECT behavior:
// Upcoming(days, now) returns acknowledgments "expiring within the given
// number of days from now" — i.e. entries whose expiry is in the future
// (after now) but before the cutoff. Already-lapsed acceptances (expiry
// in the past) are EXPIRED, not "upcoming", and must NOT be returned.
//
// store.go:382 Upcoming computes cutoff = now.AddDate(0,0,days) and
// appends every active entry where expiry.Before(cutoff), with no lower
// bound. An entry expired years ago still satisfies expiry < cutoff and
// is wrongly returned. This test fails against current code.
func Test_RedGate_UpcomingLowerBound(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during Upcoming lower-bound test: %v", r)
		}
	}()

	now := time.Date(2026, 6, 5, 0, 0, 0, 0, time.UTC)
	f := &AcceptanceFile{
		SchemaVersion: "1",
		Acknowledgments: []AcknowledgmentEntry{
			{
				ID:         "CTL.A.001@asset-1",
				ControlID:  "CTL.A.001",
				AssetID:    "asset-1",
				Reason:     "long lapsed",
				Approver:   "alice",
				ExpiryDate: "2020-01-01", // expired ~6 years before now
				Status:     AckStatusActive,
			},
		},
	}

	got := f.Upcoming(30, now)
	if len(got) != 0 {
		t.Fatalf("Upcoming(30, %s) returned %d entries for an acceptance that expired on 2020-01-01; "+
			"already-lapsed entries are expired, not upcoming, so want 0\nreturned: %+v",
			now.Format("2006-01-02"), len(got), got)
	}
}
