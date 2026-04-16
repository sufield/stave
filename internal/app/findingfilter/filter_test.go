package findingfilter

import (
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func finding(ctl string, ast string) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			AssetID:         asset.ID(ast),
			ControlSeverity: policy.SeverityHigh,
		},
	}
}

func assessment(t time.Time, findings ...remediation.Finding) *report.Assessment {
	return &report.Assessment{
		Run:      evaluation.RunInfo{Now: t},
		Findings: findings,
	}
}

var (
	t0 = time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	t1 = time.Date(2026, 3, 8, 0, 0, 0, 0, time.UTC)
	t2 = time.Date(2026, 3, 15, 0, 0, 0, 0, time.UTC)
	t3 = time.Date(2026, 3, 22, 0, 0, 0, 0, time.UTC)
)

func TestClassify_NoHistory_AllNew(t *testing.T) {
	result := Classify(Input{
		CurrentFindings: []remediation.Finding{
			finding("CTL.A.001", "asset1"),
			finding("CTL.B.001", "asset2"),
		},
		Now: t1,
	})

	if len(result.NewFindings) != 2 {
		t.Errorf("new = %d, want 2", len(result.NewFindings))
	}
	if result.SuppressedCount != 0 {
		t.Errorf("suppressed = %d, want 0", result.SuppressedCount)
	}
	if result.TotalFindings != 2 {
		t.Errorf("total = %d, want 2", result.TotalFindings)
	}
}

func TestClassify_ChronicFindingSuppressed(t *testing.T) {
	history := []*report.Assessment{
		assessment(t0,
			finding("CTL.A.001", "asset1"),
			finding("CTL.B.001", "asset2"),
		),
		assessment(t1,
			finding("CTL.A.001", "asset1"),
			finding("CTL.B.001", "asset2"),
		),
	}

	result := Classify(Input{
		CurrentFindings: []remediation.Finding{
			finding("CTL.A.001", "asset1"),
			finding("CTL.B.001", "asset2"),
			finding("CTL.C.001", "asset3"),
		},
		History: history,
		Now:     t2,
	})

	if len(result.NewFindings) != 1 {
		t.Fatalf("new = %d, want 1", len(result.NewFindings))
	}
	if result.NewFindings[0].Finding.ControlID != "CTL.C.001" {
		t.Errorf("new finding = %s, want CTL.C.001", result.NewFindings[0].Finding.ControlID)
	}
	if result.SuppressedCount != 2 {
		t.Errorf("suppressed = %d, want 2", result.SuppressedCount)
	}
}

func TestClassify_NewFindingNotSuppressed(t *testing.T) {
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "asset1")),
	}

	result := Classify(Input{
		CurrentFindings: []remediation.Finding{
			finding("CTL.A.001", "asset1"),
			finding("CTL.NEW.001", "asset-new"),
		},
		History: history,
		Now:     t1,
	})

	if len(result.NewFindings) != 1 {
		t.Fatalf("new = %d, want 1", len(result.NewFindings))
	}
	if result.NewFindings[0].Finding.ControlID != "CTL.NEW.001" {
		t.Errorf("new = %s, want CTL.NEW.001", result.NewFindings[0].Finding.ControlID)
	}
}

func TestClassify_ReturnedAfterAbsence(t *testing.T) {
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "asset1")), // present
		assessment(t1), // absent — was fixed
		assessment(t2), // absent — still fixed
	}

	result := Classify(Input{
		CurrentFindings: []remediation.Finding{
			finding("CTL.A.001", "asset1"), // returned
		},
		History: history,
		Now:     t3,
	})

	if len(result.ReturnedFindings) != 1 {
		t.Fatalf("returned = %d, want 1", len(result.ReturnedFindings))
	}
	rf := result.ReturnedFindings[0]
	if rf.Class != ClassReturned {
		t.Errorf("class = %s, want returned", rf.Class)
	}
	if rf.Finding.ControlID != "CTL.A.001" {
		t.Errorf("control = %s, want CTL.A.001", rf.Finding.ControlID)
	}
}

func TestClassify_ResolvedSinceLastRun(t *testing.T) {
	history := []*report.Assessment{
		assessment(t0,
			finding("CTL.A.001", "asset1"),
			finding("CTL.B.001", "asset2"),
		),
		assessment(t1,
			finding("CTL.A.001", "asset1"),
			finding("CTL.B.001", "asset2"),
		),
	}

	// CTL.B.001 is resolved (gone from current).
	result := Classify(Input{
		CurrentFindings: []remediation.Finding{
			finding("CTL.A.001", "asset1"),
		},
		History: history,
		Now:     t2,
	})

	if len(result.ResolvedFindings) != 1 {
		t.Fatalf("resolved = %d, want 1", len(result.ResolvedFindings))
	}
	if result.ResolvedFindings[0].ControlID != "CTL.B.001" {
		t.Errorf("resolved = %s, want CTL.B.001", result.ResolvedFindings[0].ControlID)
	}
}

func TestClassify_NewSince_FiltersByWindow(t *testing.T) {
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "asset1")), // 21 days ago
		assessment(t2, finding("CTL.A.001", "asset1")), // 7 days ago
	}

	// With 10-day window: only t2 is within window, so CTL.A.001 is chronic.
	result := Classify(Input{
		CurrentFindings: []remediation.Finding{
			finding("CTL.A.001", "asset1"),
			finding("CTL.NEW.001", "asset2"),
		},
		History:  history,
		NewSince: 10 * 24 * time.Hour,
		Now:      t3,
	})

	if len(result.NewFindings) != 1 {
		t.Fatalf("new = %d, want 1", len(result.NewFindings))
	}
	if result.NewFindings[0].Finding.ControlID != "CTL.NEW.001" {
		t.Errorf("new = %s, want CTL.NEW.001", result.NewFindings[0].Finding.ControlID)
	}
	if result.SuppressedCount != 1 {
		t.Errorf("suppressed = %d, want 1", result.SuppressedCount)
	}
}

func TestClassify_NewSince_OutsideWindow_AllNew(t *testing.T) {
	history := []*report.Assessment{
		assessment(t0, finding("CTL.A.001", "asset1")), // 21 days ago
	}

	// With 5-day window: t0 is outside, so all findings are new.
	result := Classify(Input{
		CurrentFindings: []remediation.Finding{
			finding("CTL.A.001", "asset1"),
		},
		History:  history,
		NewSince: 5 * 24 * time.Hour,
		Now:      t3,
	})

	if len(result.NewFindings) != 1 {
		t.Fatalf("new = %d, want 1", len(result.NewFindings))
	}
	if result.SuppressedCount != 0 {
		t.Errorf("suppressed = %d, want 0", result.SuppressedCount)
	}
}
