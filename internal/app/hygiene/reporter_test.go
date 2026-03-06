package hygiene

import (
	"strings"
	"testing"
	"time"
)

func TestRenderMarkdown(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	previous := now.Add(-7 * 24 * time.Hour)
	trends := []TrendMetric{
		{Name: "Current violations", Current: 10, Previous: 5},
		{Name: "Upcoming overdue", Current: 2, Previous: 2},
	}

	req := ReportRequest{
		Context: ReportContext{
			Now:         now,
			PreviousNow: previous,
			Lookback:    7 * 24 * time.Hour,
			DueSoon:     24 * time.Hour,
		},
		Snapshots: SnapshotStats{Active: 3, Archived: 1, Total: 4, PruneCandidates: 0, RetentionTier: "critical", RetentionDuration: 30 * 24 * time.Hour, KeepMin: 2},
		Risks:     RiskStats{CurrentViolations: 10, Overdue: 2, DueNow: 0, DueSoon: 1, Later: 0, UpcomingTotal: 3},
		Trends:    trends,
	}
	out := req.RenderMarkdown()

	if !strings.Contains(out, "# Snapshot Hygiene Report") {
		t.Error("expected report to contain title")
	}
	if !strings.Contains(out, "## Lifecycle Inventory") {
		t.Error("expected Lifecycle Inventory section")
	}
	if !strings.Contains(out, "## Risk Posture & Trends") {
		t.Error("expected Risk Posture & Trends section")
	}
	// Positive change should show ↑
	if !strings.Contains(out, "↑ 5") {
		t.Error("expected positive trend change to show ↑ 5")
	}
	if !strings.Contains(out, "| Current violations | 10 | 5 | ↑ 5 |") {
		t.Error("expected trend row with ↑ 5")
	}
	if !strings.Contains(out, "stave snapshot hygiene") {
		t.Error("expected footer")
	}
}
