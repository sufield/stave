package bisect

import (
	"context"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

func makeSnap(t time.Time, violated bool) asset.Snapshot {
	return asset.Snapshot{
		CapturedAt: t,
		Assets: []asset.Asset{{
			ID:   "test-resource",
			Type: "aws_s3_bucket",
			Properties: map[string]any{
				"storage": map[string]any{
					"access": map[string]any{"public_read": violated},
				},
			},
		}},
	}
}

func base() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func day(n int) time.Time {
	return base().Add(time.Duration(n) * 24 * time.Hour)
}

// timeBasedEvaluator creates an evaluator that looks up violation status by timestamp.
func timeBasedEvaluator(violations map[time.Time]bool) Evaluator {
	return func(_ context.Context, snap asset.Snapshot) (bool, error) {
		return violations[snap.CapturedAt], nil
	}
}

func TestBisect_MonotonicSingleWindow(t *testing.T) {
	// PASS PASS PASS FAIL FAIL FAIL FAIL FAIL
	snaps := make([]asset.Snapshot, 8)
	violations := make(map[time.Time]bool)
	for i := range snaps {
		snaps[i] = makeSnap(day(i), i >= 3)
		violations[day(i)] = i >= 3
	}

	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), snaps, ModeBisect, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasViolation() {
		t.Fatal("expected violation")
	}
	if len(result.Windows) != 1 {
		t.Fatalf("expected 1 window, got %d", len(result.Windows))
	}
	w := result.Windows[0]
	if !w.EntryBefore.Equal(day(2)) {
		t.Errorf("EntryBefore = %v, want day(2)", w.EntryBefore)
	}
	if !w.EntryAfter.Equal(day(3)) {
		t.Errorf("EntryAfter = %v, want day(3)", w.EntryAfter)
	}
	if !result.IsMonotonic {
		t.Error("expected monotonic history")
	}
}

func TestScan_NonMonotonicThreeWindows(t *testing.T) {
	// P P F F P P F F P F F F
	pattern := []bool{false, false, true, true, false, false, true, true, false, true, true, true}
	snaps := make([]asset.Snapshot, len(pattern))
	violations := make(map[time.Time]bool)
	for i := range snaps {
		snaps[i] = makeSnap(day(i), pattern[i])
		violations[day(i)] = pattern[i]
	}

	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), snaps, ModeScan, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Windows) != 3 {
		t.Fatalf("expected 3 windows, got %d", len(result.Windows))
	}
	if result.IsMonotonic {
		t.Error("expected non-monotonic")
	}
	// Window 1: day(2)-day(3), remediated
	if result.Windows[0].IsOngoing {
		t.Error("window 1 should be remediated")
	}
	// Window 3: day(9)-day(11), ongoing
	if !result.Windows[2].IsOngoing {
		t.Error("window 3 should be ongoing")
	}
}

func TestBisect_NeverViolated(t *testing.T) {
	snaps := make([]asset.Snapshot, 8)
	violations := make(map[time.Time]bool)
	for i := range snaps {
		snaps[i] = makeSnap(day(i), false)
		violations[day(i)] = false
	}

	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), snaps, ModeBisect, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.HasViolation() {
		t.Fatal("expected no violation")
	}
}

func TestBisect_AlwaysViolated(t *testing.T) {
	snaps := make([]asset.Snapshot, 8)
	violations := make(map[time.Time]bool)
	for i := range snaps {
		snaps[i] = makeSnap(day(i), true)
		violations[day(i)] = true
	}

	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), snaps, ModeBisect, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasViolation() {
		t.Fatal("expected violation")
	}
	w := result.Windows[0]
	if !w.EntryAfter.Equal(day(0)) {
		t.Errorf("violation should predate archive, got %v", w.EntryAfter)
	}
}

func TestBisect_SingleSnapshot(t *testing.T) {
	violations := map[time.Time]bool{day(0): true}
	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), []asset.Snapshot{makeSnap(day(0), true)}, ModeBisect, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasViolation() {
		t.Fatal("expected violation for single violated snapshot")
	}
}

func TestBisect_TwoSnapshotsPassFail(t *testing.T) {
	violations := map[time.Time]bool{day(0): false, day(1): true}
	snaps := []asset.Snapshot{makeSnap(day(0), false), makeSnap(day(1), true)}

	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), snaps, ModeBisect, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Windows) != 1 {
		t.Fatalf("expected 1 window, got %d", len(result.Windows))
	}
	w := result.Windows[0]
	if !w.EntryBefore.Equal(day(0)) || !w.EntryAfter.Equal(day(1)) {
		t.Errorf("transition should be day(0)→day(1), got %v→%v", w.EntryBefore, w.EntryAfter)
	}
}

func TestBisect_TwoSnapshotsBothPass(t *testing.T) {
	violations := map[time.Time]bool{day(0): false, day(1): false}
	snaps := []asset.Snapshot{makeSnap(day(0), false), makeSnap(day(1), false)}

	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), snaps, ModeBisect, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.HasViolation() {
		t.Fatal("expected no violation")
	}
}

func TestScan_NeverViolated(t *testing.T) {
	snaps := make([]asset.Snapshot, 4)
	violations := make(map[time.Time]bool)
	for i := range snaps {
		snaps[i] = makeSnap(day(i), false)
		violations[day(i)] = false
	}

	eng := &Engine{Evaluate: timeBasedEvaluator(violations)}
	result, err := eng.Run(context.Background(), snaps, ModeScan, "CTL.TEST.001", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.HasViolation() {
		t.Fatal("expected no violation in scan mode")
	}
	if !result.IsMonotonic {
		t.Error("no violations should be monotonic")
	}
}
