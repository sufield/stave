package asset

import (
	"testing"
	"time"
)

func TestSnapshots_TemporalBounds(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)

	s := Snapshots{
		{CapturedAt: t2},
		{CapturedAt: t1},
		{CapturedAt: t3},
	}
	earliest, latest := s.TemporalBounds()
	if !earliest.Equal(t1) {
		t.Errorf("earliest = %v, want %v", earliest, t1)
	}
	if !latest.Equal(t3) {
		t.Errorf("latest = %v, want %v", latest, t3)
	}
}

func TestSnapshots_TemporalBounds_Empty(t *testing.T) {
	var s Snapshots
	earliest, latest := s.TemporalBounds()
	if !earliest.IsZero() || !latest.IsZero() {
		t.Errorf("expected zero times for empty snapshots, got earliest=%v latest=%v", earliest, latest)
	}
}

func TestSnapshots_UniqueAssetCount(t *testing.T) {
	s := Snapshots{
		{Assets: []Asset{{ID: "a"}, {ID: "b"}}},
		{Assets: []Asset{{ID: "b"}, {ID: "c"}}},
	}
	if got := s.UniqueAssetCount(); got != 3 {
		t.Errorf("UniqueAssetCount() = %d, want 3", got)
	}
}

func TestSnapshots_UniqueAssetCount_Empty(t *testing.T) {
	var s Snapshots
	if got := s.UniqueAssetCount(); got != 0 {
		t.Errorf("UniqueAssetCount() = %d, want 0", got)
	}
}
