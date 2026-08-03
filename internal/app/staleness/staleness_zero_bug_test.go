package staleness

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func TestCheck_SnapshotWithZeroCapturedAt(t *testing.T) {
	// Snapshot with explicit zero time
	snaps := []asset.Snapshot{
		{
			CapturedAt: time.Time{}, // zero time
		},
	}

	threshold := 24 * time.Hour
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	res := Check(snaps, threshold, now)

	if !res.Stale {
		t.Errorf("expected Stale true for zero timestamp snapshot")
	}

	if res.Message != "snapshot capture timestamp missing or zero" {
		t.Errorf("expected clean message for zero timestamp, got %q", res.Message)
	}
}
