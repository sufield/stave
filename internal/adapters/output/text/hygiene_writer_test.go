package text

import (
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/app/hygiene"
)

func TestWriteHygieneReport(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	previous := now.Add(-7 * 24 * time.Hour)
	trends := []hygiene.TrendMetric{
		{Name: "Current violations", Current: 10, Previous: 5},
		{Name: "Upcoming overdue", Current: 2, Previous: 2},
	}

	req := hygiene.ReportRequest{
		Context: hygiene.ReportContext{
			Now:         now,
			PreviousNow: previous,
			Lookback:    7 * 24 * time.Hour,
			DueSoon:     24 * time.Hour,
		},
		Snapshots: hygiene.SnapshotStats{Active: 3, Archived: 1, Total: 4, PruneCandidates: 0, RetentionTier: "critical", RetentionDuration: 30 * 24 * time.Hour, KeepMin: 2},
		Risks:     hygiene.RiskStats{CurrentViolations: 10, Overdue: 2, DueNow: 0, DueSoon: 1, Later: 0, UpcomingTotal: 3},
		Trends:    trends,
	}

	var b strings.Builder
	if err := WriteHygieneReport(&b, req); err != nil {
		t.Fatalf("WriteHygieneReport: %v", err)
	}
	out := b.String()

	if !strings.Contains(out, "# Snapshot Hygiene Report") {
		t.Error("expected report to contain title")
	}
	if !strings.Contains(out, "## Lifecycle Inventory") {
		t.Error("expected Lifecycle Inventory section")
	}
	if !strings.Contains(out, "## Risk Posture & Trends") {
		t.Error("expected Risk Posture & Trends section")
	}
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
