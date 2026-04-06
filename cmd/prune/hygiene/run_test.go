package hygiene

import (
	"strings"
	"testing"
	"time"

	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
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
	reportReq := appcontracts.HygieneAssessment{
		AuditContext: appcontracts.AuditContext{
			Now:             now,
			PreviousAuditAt: previous,
			LookbackWindow:  7 * 24 * time.Hour,
			SLAWarning:      24 * time.Hour,
		},
		Evidence: appcontracts.EvidenceInventory{
			CurrentInventory:   6,
			HistoricalEvidence: 2,
			PurgeCandidates:    1,
			ComplianceTier:     "critical",
			RetentionPolicy:    30 * 24 * time.Hour,
			MinEvidenceCount:   2,
		},
		SLAPosture: appcontracts.SLAPosture{
			ActiveFindings:  4,
			SLABreaches:     1,
			BreachingNow:    1,
			NearBreach:      2,
			CompliantWindow: 0,
		},
		ExposureHistory: []evaluation.TrendMetric{
			{Name: "Current violations", Current: 4, Previous: 6},
		},
	}
	var b strings.Builder
	if err := outtext.WriteHygieneReport(&b, reportReq); err != nil {
		t.Fatalf("WriteHygieneReport: %v", err)
	}
	out := b.String()

	contains := []string{
		"# Snapshot Hygiene Report",
		"## Lifecycle Inventory",
		"| Total snapshots | 8 |",
		"| Archived snapshots | 2 |",
		"| Prune candidates (current) | 1 |",
		"## Current Risk Status",
		"| Current violations | 4 |",
		"| Upcoming overdue | 1 |",
		"## Risk SecurityState & Trends",
		"| Current violations | 4 | 6 | ↓ -2 |",
	}
	for _, needle := range contains {
		if !strings.Contains(out, needle) {
			t.Fatalf("expected report to contain %q", needle)
		}
	}
}
