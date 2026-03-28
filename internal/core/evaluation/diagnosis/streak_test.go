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

	s := newSession(NewInput(
		snapshots, []policy.ControlDefinition{ctl}, nil, 0, 0, 0, base.Add(1*time.Hour), mustPredicateEval(),
	), 0)
	maxStreak, ctlID := s.globalMaxStreak()

	if ctlID != ctl.ID.String() {
		t.Fatalf("control id = %q, want %q", ctlID, ctl.ID)
	}
	if maxStreak != 2*time.Hour {
		t.Fatalf("max streak = %v, want %v", maxStreak, 2*time.Hour)
	}
}
