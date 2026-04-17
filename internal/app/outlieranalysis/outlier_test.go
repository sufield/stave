package outlieranalysis

import (
	"testing"

	"github.com/sufield/stave/internal/app/consolidate"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func mkAssessment(findings ...remediation.Finding) report.Assessment {
	return report.Assessment{
		Findings: findings,
	}
}

func mkFinding(ctlID string, astID string, dwellHours float64) remediation.Finding {
	return remediation.Finding{
		Finding: evaluation.Finding{
			ControlID:       kernel.ControlID(ctlID),
			AssetID:         asset.ID(astID),
			ControlSeverity: policy.SeverityHigh,
			Evidence: evaluation.Evidence{
				UnsafeDurationHours: dwellHours,
			},
		},
	}
}

func TestAnalyze_FailingAccountsIdentified(t *testing.T) {
	consol := consolidate.ConsolidatedReport{
		Accounts: []consolidate.AccountSummary{
			{AccountID: "acct-1", AccountName: "Production"},
			{AccountID: "acct-2", AccountName: "Staging"},
			{AccountID: "acct-3", AccountName: "Dev"},
		},
	}

	assessments := map[string]report.Assessment{
		"acct-1": mkAssessment(mkFinding("s3_public_read", "bucket-1", 48)),
		"acct-2": mkAssessment(), // passing
		"acct-3": mkAssessment(mkFinding("s3_public_read", "bucket-3", 168)),
	}

	result := Analyze(Input{
		Consolidated: consol,
		Assessments:  assessments,
		ControlID:    "s3_public_read",
	})

	if result.FailingCount != 2 {
		t.Errorf("expected 2 failing accounts, got %d", result.FailingCount)
	}
	if result.PassingCount != 1 {
		t.Errorf("expected 1 passing account, got %d", result.PassingCount)
	}
	if len(result.FailingAccounts) != 2 {
		t.Fatalf("expected 2 failing account entries, got %d", len(result.FailingAccounts))
	}

	// Verify dwell days are calculated correctly.
	for _, acct := range result.FailingAccounts {
		switch acct.AccountID {
		case "acct-1":
			if acct.DwellDays != 2 { // 48h / 24
				t.Errorf("acct-1 dwell days: got %v, want 2", acct.DwellDays)
			}
		case "acct-3":
			if acct.DwellDays != 7 { // 168h / 24
				t.Errorf("acct-3 dwell days: got %v, want 7", acct.DwellDays)
			}
		}
	}
}

func TestAnalyze_MissingAssessmentCountsAsPassing(t *testing.T) {
	consol := consolidate.ConsolidatedReport{
		Accounts: []consolidate.AccountSummary{
			{AccountID: "acct-1", AccountName: "Production"},
			{AccountID: "acct-2", AccountName: "Staging"},
		},
	}

	// Only acct-1 has an assessment (and it passes).
	assessments := map[string]report.Assessment{
		"acct-1": mkAssessment(),
	}

	result := Analyze(Input{
		Consolidated: consol,
		Assessments:  assessments,
		ControlID:    "s3_public_read",
	})

	if result.PassingCount != 2 {
		t.Errorf("expected 2 passing (including missing assessment), got %d", result.PassingCount)
	}
	if result.FailingCount != 0 {
		t.Errorf("expected 0 failing, got %d", result.FailingCount)
	}
}
