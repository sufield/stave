package orgtrend

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

var (
	day = 24 * time.Hour
	t0  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t90 = t0.Add(90 * day)
)

func mkAssessment(t time.Time, totalAssets, violations int, findings ...remediation.Finding) *report.Assessment {
	return &report.Assessment{
		Run:      evaluation.RunInfo{Now: t},
		Summary:  evaluation.ComplianceSummary{TotalAssets: totalAssets, Violations: violations},
		Findings: findings,
	}
}

func finding(ctl string, ast string, sev policy.Severity) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctl),
			AssetID:         asset.ID(ast),
			ControlSeverity: sev,
		},
	}
}

func TestCompute_RegressingAccountIdentified(t *testing.T) {
	accounts := []AccountTimeSeries{
		{
			AccountID: "prod-us-east",
			Runs: []*report.Assessment{
				mkAssessment(t0, 100, 5,
					finding("CTL.A.001", "a1", policy.SeverityHigh),
				),
				mkAssessment(t90, 100, 20,
					finding("CTL.A.001", "a1", policy.SeverityHigh),
					finding("CTL.B.001", "a2", policy.SeverityCritical),
				),
			},
		},
		{
			AccountID: "staging",
			Runs: []*report.Assessment{
				mkAssessment(t0, 100, 30),
				mkAssessment(t90, 100, 10),
			},
		},
	}

	result := Compute(Input{
		Accounts: accounts,
		Window:   90 * day,
		Now:      t90,
	})

	if result.AccountCount != 2 {
		t.Fatalf("accounts = %d, want 2", result.AccountCount)
	}

	// Find the regressing account.
	var regressing *AccountTrend
	for i := range result.Accounts {
		if result.Accounts[i].AccountID == "prod-us-east" {
			regressing = &result.Accounts[i]
			break
		}
	}
	if regressing == nil {
		t.Fatal("prod-us-east not found")
	}
	if regressing.Trajectory != TrajectoryRegressing {
		t.Errorf("trajectory = %s, want REGRESSING", regressing.Trajectory)
	}
	if regressing.Delta >= 0 {
		t.Errorf("delta = %.1f, want negative", regressing.Delta)
	}

	// Regression driver should exist.
	if len(result.RegressionDrivers) == 0 {
		t.Error("expected regression drivers")
	}
}

func TestCompute_OrgAggregateWeightedMean(t *testing.T) {
	accounts := []AccountTimeSeries{
		{
			AccountID: "account-a",
			Runs: []*report.Assessment{
				mkAssessment(t90, 100, 10),
			},
		},
		{
			AccountID: "account-b",
			Runs: []*report.Assessment{
				mkAssessment(t90, 100, 20),
			},
		},
	}

	result := Compute(Input{
		Accounts: accounts,
		Window:   90 * day,
		Now:      t90,
	})

	// Score for account-a: (1 - 10/100) * 100 = 90
	// Score for account-b: (1 - 20/100) * 100 = 80
	// Weighted: not simple average, weighted by finding count
	if result.OrgScore < 70 || result.OrgScore > 95 {
		t.Errorf("org score = %.1f, want between 70-95", result.OrgScore)
	}
}

func TestCompute_EmptyAccounts(t *testing.T) {
	result := Compute(Input{
		Window: 90 * day,
		Now:    t90,
	})

	if result.AccountCount != 0 {
		t.Errorf("accounts = %d, want 0", result.AccountCount)
	}
}

func TestCompute_WindowFilter(t *testing.T) {
	// Only the t90 assessment is within a 30-day window from t90.
	accounts := []AccountTimeSeries{
		{
			AccountID: "test",
			Runs: []*report.Assessment{
				mkAssessment(t0, 100, 50),  // outside window
				mkAssessment(t90, 100, 10), // inside window
			},
		},
	}

	result := Compute(Input{
		Accounts: accounts,
		Window:   30 * day,
		Now:      t90,
	})

	if len(result.Accounts) != 1 {
		t.Fatalf("accounts = %d, want 1", len(result.Accounts))
	}
	// With only one assessment in window, delta should be 0.
	if result.Accounts[0].Delta != 0 {
		t.Errorf("delta = %.1f, want 0 (single assessment)", result.Accounts[0].Delta)
	}
}
