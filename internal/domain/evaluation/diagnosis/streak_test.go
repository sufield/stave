package diagnosis

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestComputeMaxUnsafeStreakPerControl_ClampsNowToLatestSnapshot(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	ctl := policy.ControlDefinition{
		ID:   "CTL.TEST.001",
		Name: "test",
		UnsafePredicate: policy.UnsafePredicate{
			Any: []policy.PredicateRule{{Field: "properties.public", Op: "eq", Value: true}},
		},
	}

	snapshots := []asset.Snapshot{
		{
			CapturedAt: base,
			Resources: []asset.Asset{
				{ID: "r1", Properties: map[string]any{"public": true}},
			},
		},
		{
			CapturedAt: base.Add(2 * time.Hour),
			Resources: []asset.Asset{
				{ID: "r1", Properties: map[string]any{"public": true}},
			},
		},
	}

	maxStreak, ctlID := computeMaxUnsafeStreakPerControl(NewInput(
		Params{
			Snapshots: snapshots,
			Controls:  []policy.ControlDefinition{ctl},
			Now:       base.Add(1 * time.Hour), // earlier than latest snapshot
			Findings:  []evaluation.Finding{},
		},
	))

	if ctlID != ctl.ID.String() {
		t.Fatalf("control id = %q, want %q", ctlID, ctl.ID)
	}
	if maxStreak != 2*time.Hour {
		t.Fatalf("max streak = %v, want %v", maxStreak, 2*time.Hour)
	}
}
