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

func TestStalenessHours_DomainMethods(t *testing.T) {
	sh := StalenessHours(72.0)

	if sh.Value() != 72.0 {
		t.Errorf("Value() = %f, want 72.0", sh.Value())
	}
	if sh.Days() != 3.0 {
		t.Errorf("Days() = %f, want 3.0", sh.Days())
	}
	if !sh.IsStale(StalenessHours(48.0)) {
		t.Error("IsStale() = false, want true for 72h > 48h")
	}
	if sh.IsStale(StalenessHours(96.0)) {
		t.Error("IsStale() = true, want false for 72h < 96h")
	}
	if gap := sh.Gap(StalenessHours(48.0)); gap != 24.0 {
		t.Errorf("Gap() = %f, want 24.0", gap.Value())
	}
	if gap := sh.Gap(StalenessHours(96.0)); gap != 0.0 {
		t.Errorf("Gap() for non-stale = %f, want 0.0", gap.Value())
	}
}
