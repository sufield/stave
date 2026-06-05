package diagnosis

import (
	"errors"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// Test_RedGate_StreakEvalErrorFreeze asserts the documented contract that an
// inconclusive evaluation (Eval returns a non-nil error) must FREEZE an
// in-progress unsafe streak rather than end it. The parallel risk view in
// upcoming.go computeAssetStates explicitly "freeze[s] streak, do not reset"
// on an eval error; analyzeAssetStreak must agree.
//
// History: three observations at t=0h, t=24h, t=48h with EndTime=72h.
// Eval returns (true, nil) at 0h and 48h, and (false, error) at 24h.
// Because the error point must NOT reset the streak, the single continuous
// unsafe period spans 0h..72h, so the correct maxStreak is 72h.
//
// The current (buggy) code routes the error point into the else branch, which
// calls endStreak(24h): finalizes a 24h streak, then restarts at 48h and
// finalizes another 24h streak at EndTime, yielding maxStreak == 24h.
func Test_RedGate_StreakEvalErrorFreeze(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic in Test_RedGate_StreakEvalErrorFreeze: %v", r)
		}
	}()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	points := []observation{
		{at: base},                     // t=0h
		{at: base.Add(24 * time.Hour)}, // t=24h (inconclusive)
		{at: base.Add(48 * time.Hour)}, // t=48h
	}
	endTime := base.Add(72 * time.Hour)

	evalErr := errors.New("malformed property: inconclusive evaluation")

	// Build a time-aware eval by stamping the timestamp into the asset ID.
	for i := range points {
		points[i].state = asset.Asset{ID: asset.ID(points[i].at.Format(time.RFC3339))}
	}
	timeAwareEval := func(_ policy.ControlDefinition, a asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		switch string(a.ID) {
		case base.Add(24 * time.Hour).Format(time.RFC3339):
			return false, evalErr // inconclusive: must freeze, not reset
		default:
			return true, nil // unsafe
		}
	}

	req := &assetStreakRequest{
		Points:  points,
		Control: policy.ControlDefinition{},
		EndTime: endTime,
		Eval:    timeAwareEval,
	}

	maxStreak, matched := analyzeAssetStreak(req)

	if !matched {
		t.Fatalf("expected matched=true (unsafe points present), got false")
	}

	want := 72 * time.Hour
	if maxStreak != want {
		t.Fatalf("maxStreak = %v, want %v: an inconclusive (eval-error) point must FREEZE the in-progress unsafe streak, not end it; the continuous unsafe period 0h..72h must report as a single 72h streak", maxStreak, want)
	}
}
