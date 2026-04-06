package text

import (
	"strings"
	"testing"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

func TestWriteHygieneReport(t *testing.T) {
	now := time.Date(2026, 1, 20, 0, 0, 0, 0, time.UTC)
	previous := now.Add(-7 * 24 * time.Hour)
	trends := []evaluation.TrendMetric{
		{Name: "Current violations", Current: 10, Previous: 5},
		{Name: "Upcoming overdue", Current: 2, Previous: 2},
	}

	req := appcontracts.HygieneAssessment{
		AuditContext: appcontracts.AuditContext{
			Now:             now,
			PreviousAuditAt: previous,
			LookbackWindow:  7 * 24 * time.Hour,
			SLAWarning:      24 * time.Hour,
		},
		Evidence:        appcontracts.EvidenceInventory{CurrentInventory: 3, HistoricalEvidence: 1, PurgeCandidates: 0, ComplianceTier: "critical", RetentionPolicy: 30 * 24 * time.Hour, MinEvidenceCount: 2},
		SLAPosture:      appcontracts.SLAPosture{ActiveFindings: 10, SLABreaches: 2, BreachingNow: 0, NearBreach: 1, CompliantWindow: 0},
		ExposureHistory: trends,
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
	if !strings.Contains(out, "## Risk SecurityState & Trends") {
		t.Error("expected Risk SecurityState & Trends section")
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
