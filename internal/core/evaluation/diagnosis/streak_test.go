package diagnosis

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestComputeMaxUnsafeStreakPerControl_ClampsNowToLatestSnapshot(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ctl := policy.ControlDefinition{
		ID:   "CTL.TEST.001",
		Name: "test",
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{{Field: predicate.NewFieldPath("properties.public"), Op: predicate.OpEq, Value: policy.Bool(true)}},
		},
	}

	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Assets: []asset.Asset{
				{ID: "r1", Properties: map[string]any{"public": true}},
			},
		},
		{
			CapturedAt: base.Add(2 * time.Hour),
			Assets: []asset.Asset{
				{ID: "r1", Properties: map[string]any{"public": true}},
			},
		},
	}

	s := newSession(NewInput(Input{
		Snapshots:         snapshots,
		Controls:          []policy.ControlDefinition{ctl},
		Findings:          nil,
		ViolationsFound:   0,
		AttackSurface:     0,
		MaxUnsafeDuration: 0,
		Now:               base.Add(1 * time.Hour),
		PredicateEval:     mustPredicateEval(),
	}), 0)
	maxStreak, ctlID := s.globalMaxStreak()

	if ctlID != ctl.ID.String() {
		t.Fatalf("control id = %q, want %q", ctlID, ctl.ID)
	}
	if maxStreak != 2*time.Hour {
		t.Fatalf("max streak = %v, want %v", maxStreak, 2*time.Hour)
	}
}

// TestAnalyzeAssetStreak_ReportsLongestOfMultipleStreaks pins the
// max-selection semantics of analyzeAssetStreak's safe-branch endStreak:
// when one asset's history contains two separate unsafe streaks (unsafe →
// safe → unsafe), the reported maxStreak must be the LONGEST streak, not
// the last one.
//
// History (one asset): unsafe 0h,24h; safe 48h (ends a 48h streak); unsafe
// 60h,72h; EndTime 84h (ends a 24h streak). The longest continuous unsafe
// period is 0h..48h = 48h.
//
// Guards the safe-branch comparison `if d := tracker.endStreak(pt.at); d >
// maxStreak` (streak.go:78): a mutant that inverts it (d <= maxStreak) drops
// the first, longer streak and returns the trailing 24h streak instead.
func TestAnalyzeAssetStreak_ReportsLongestOfMultipleStreaks(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	points := []observation{
		{at: base},                     // 0h  unsafe (streak A start)
		{at: base.Add(24 * time.Hour)}, // 24h unsafe (streak A extend)
		{at: base.Add(48 * time.Hour)}, // 48h safe   (streak A ends -> 48h)
		{at: base.Add(60 * time.Hour)}, // 60h unsafe (streak B start)
		{at: base.Add(72 * time.Hour)}, // 72h unsafe (streak B extend)
	}
	endTime := base.Add(84 * time.Hour) // streak B ends -> 24h

	// Stamp each point's timestamp into its asset ID so the eval can be
	// time-aware; only the 48h point is safe.
	for i := range points {
		points[i].state = asset.Asset{ID: asset.ID(points[i].at.Format(time.RFC3339))}
	}
	safeAt := base.Add(48 * time.Hour).Format(time.RFC3339)
	timeAwareEval := func(_ policy.ControlDefinition, a asset.Asset, _ []asset.CloudIdentity) (bool, error) {
		if string(a.ID) == safeAt {
			return false, nil // safe: ends streak A
		}
		return true, nil // unsafe
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
	want := 48 * time.Hour
	if maxStreak != want {
		t.Fatalf("maxStreak = %v, want %v: analyzeAssetStreak must report the LONGEST of multiple unsafe streaks (0h..48h), not the trailing 24h streak", maxStreak, want)
	}
}
