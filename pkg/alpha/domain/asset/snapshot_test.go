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
	min, max := s.TemporalBounds()
	if !min.Equal(t1) {
		t.Errorf("min = %v, want %v", min, t1)
	}
	if !max.Equal(t3) {
		t.Errorf("max = %v, want %v", max, t3)
	}
}

func TestSnapshots_TemporalBounds_Empty(t *testing.T) {
	var s Snapshots
	min, max := s.TemporalBounds()
	if !min.IsZero() || !max.IsZero() {
		t.Errorf("expected zero times for empty snapshots, got min=%v max=%v", min, max)
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
