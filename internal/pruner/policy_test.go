package pruner

import (
	"testing"
	"time"
)

func TestPlanPrune(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	items := []Candidate{
		{CapturedAt: now.AddDate(0, 0, -40)},
		{CapturedAt: now.AddDate(0, 0, -35)},
		{CapturedAt: now.AddDate(0, 0, -20)},
		{CapturedAt: now.AddDate(0, 0, -5)},
	}

	out := PlanPrune(items, Criteria{
		Now:       now,
		OlderThan: 30 * 24 * time.Hour,
		KeepMin:   2,
	})
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
	if !out[0].CapturedAt.Equal(items[0].CapturedAt) || !out[1].CapturedAt.Equal(items[1].CapturedAt) {
		t.Fatalf("unexpected selected candidates: %+v", out)
	}
}

func TestPlanPrune_KeepFloor(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	items := []Candidate{
		{CapturedAt: now.AddDate(0, 0, -40)},
		{CapturedAt: now.AddDate(0, 0, -35)},
	}

	out := PlanPrune(items, Criteria{
		Now:       now,
		OlderThan: 30 * 24 * time.Hour,
		KeepMin:   2,
	})
	if len(out) != 0 {
		t.Fatalf("len(out) = %d, want 0", len(out))
	}
}
