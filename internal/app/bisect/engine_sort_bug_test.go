package bisect

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func TestEngine_Run_UnsortedSnapshotsSortedChronologically(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)

	// Chronological sequence:
	// t0: PASS
	// t1: FAIL
	// t2: FAIL
	s0 := asset.Snapshot{CapturedAt: t0}
	s1 := asset.Snapshot{CapturedAt: t1}
	s2 := asset.Snapshot{CapturedAt: t2}

	// Pass snapshots in reverse/unsorted order: s2, s0, s1
	unsorted := []asset.Snapshot{s2, s0, s1}

	eng := &Engine{
		Evaluate: func(ctx context.Context, snap asset.Snapshot) (bool, error) {
			// Violates at t1 and t2
			return snap.CapturedAt.Equal(t1) || snap.CapturedAt.Equal(t2), nil
		},
	}

	res, err := eng.Run(context.Background(), unsorted, ModeBisect, "CTL.S3.001", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !res.HasViolation() {
		t.Fatalf("expected violation window to be found for unsorted snapshots")
	}

	// EntryBefore must be t0 (last pass before violation at t1)
	if !res.Windows[0].EntryBefore.Equal(t0) {
		t.Errorf("expected EntryBefore to be %v (t0), got %v", t0, res.Windows[0].EntryBefore)
	}
	if !res.Windows[0].EntryAfter.Equal(t1) {
		t.Errorf("expected EntryAfter to be %v (t1), got %v", t1, res.Windows[0].EntryAfter)
	}
}
