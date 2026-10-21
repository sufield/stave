package staleness

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func TestCheck_StaleDetected(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	snaps := []asset.Snapshot{
		{CapturedAt: now.Add(-72 * time.Hour)}, // 72 hours old
	}

	r := Check(snaps, 48*time.Hour, now)

	if !r.Stale {
		t.Error("expected stale (72h > 48h threshold)")
	}
	if r.GapHrs < 23 {
		t.Errorf("gap = %.0f, want ~24", r.GapHrs)
	}
}

func TestCheck_FreshPasses(t *testing.T) {
	now := time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC)
	snaps := []asset.Snapshot{
		{CapturedAt: now.Add(-4 * time.Hour)}, // 4 hours old
	}

	r := Check(snaps, 48*time.Hour, now)

	if r.Stale {
		t.Error("expected fresh (4h < 48h threshold)")
	}
}

func TestCheck_NoSnapshots(t *testing.T) {
	r := Check(nil, 48*time.Hour, time.Now())
	if !r.Stale {
		t.Error("expected stale with no snapshots")
	}
}
