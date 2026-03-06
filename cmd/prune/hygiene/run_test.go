package hygiene

import (
	"strings"
	"testing"
	"time"

	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
	"github.com/sufield/stave/internal/domain/asset"
)

func TestFilterSnapshotsBefore(t *testing.T) {
	base := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	snapshots := []asset.Snapshot{
		{CapturedAt: base.Add(-2 * time.Hour)},
		{CapturedAt: base.Add(-10 * time.Hour)},
		{CapturedAt: base.Add(1 * time.Hour)},
	}
	got := filterSnapshotsBefore(snapshots, base)
	if len(got) != 2 {
		t.Fatalf("expected 2 snapshots before cutoff, got %d", len(got))
	}
	if !got[0].CapturedAt.Before(got[1].CapturedAt) {
		t.Fatalf("expected sorted snapshots in ascending captured_at order")
	}
}

func TestRenderMarkdown(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	previous := now.Add(-7 * 24 * time.Hour)
	reportReq := hygieneapp.ReportRequest{
		Context: hygieneapp.ReportContext{
			Now:         now,
			PreviousNow: previous,
			Lookback:    7 * 24 * time.Hour,
			DueSoon:     24 * time.Hour,
		},
		Snapshots: hygieneapp.SnapshotStats{
			Active:            6,
			Archived:          2,
			Total:             8,
			PruneCandidates:   1,
			RetentionTier:     "critical",
			RetentionDuration: 30 * 24 * time.Hour,
			KeepMin:           2,
		},
		Risks: hygieneapp.RiskStats{
			CurrentViolations: 4,
			Overdue:           1,
			DueNow:            1,
			DueSoon:           2,
			Later:             0,
			UpcomingTotal:     4,
		},
		Trends: []hygieneapp.TrendMetric{
			{Name: "Current violations", Current: 4, Previous: 6},
		},
	}
	out := reportReq.RenderMarkdown()

	contains := []string{
		"# Snapshot Hygiene Report",
		"## Lifecycle Inventory",
		"| Total snapshots | 8 |",
		"| Archived snapshots | 2 |",
		"| Prune candidates (current) | 1 |",
		"## Current Risk Status",
		"| Current violations | 4 |",
		"| Upcoming overdue | 1 |",
		"## Risk Posture & Trends",
		"| Current violations | 4 | 6 | ↓ -2 |",
	}
	for _, needle := range contains {
		if !strings.Contains(out, needle) {
			t.Fatalf("expected report to contain %q", needle)
		}
	}
}
