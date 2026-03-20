package cleanup

import (
	"testing"
	"time"

	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/pruner"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

func TestPlanPrune_RespectsKeepMin(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{Name: "a.json", CapturedAt: now.AddDate(0, 0, -40)},
		{Name: "b.json", CapturedAt: now.AddDate(0, 0, -35)},
		{Name: "c.json", CapturedAt: now.AddDate(0, 0, -20)},
		{Name: "d.json", CapturedAt: now.AddDate(0, 0, -5)},
	}

	deletions := pruneshared.PlanPrune(files, retention.Criteria{Now: now, OlderThan: 30 * 24 * time.Hour, KeepMin: 2})
	if len(deletions) != 2 {
		t.Fatalf("expected 2 deletions, got %d", len(deletions))
	}
	if deletions[0].Name != "a.json" || deletions[1].Name != "b.json" {
		t.Fatalf("expected oldest files to be pruned first, got %s and %s", deletions[0].Name, deletions[1].Name)
	}
}

func TestPlanPrune_NoDeletionsWhenWouldDropBelowKeepMin(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	files := []pruner.SnapshotFile{
		{Name: "a.json", CapturedAt: now.AddDate(0, 0, -40)},
		{Name: "b.json", CapturedAt: now.AddDate(0, 0, -35)},
	}

	deletions := pruneshared.PlanPrune(files, retention.Criteria{Now: now, OlderThan: 30 * 24 * time.Hour, KeepMin: 2})
	if len(deletions) != 0 {
		t.Fatalf("expected 0 deletions, got %d", len(deletions))
	}
}
