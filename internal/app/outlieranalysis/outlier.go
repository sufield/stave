// Package outlieranalysis provides cross-account control outlier detection
// by partitioning accounts into passing and failing for a specific control.
package outlieranalysis

import (
	"github.com/sufield/stave/internal/app/consolidate"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// AccountStatus records a single account's status for the analyzed control.
type AccountStatus struct {
	AccountID   string  `json:"account_id"`
	AccountName string  `json:"account_name"`
	DwellDays   float64 `json:"dwell_days"`
}

// OutlierReport partitions accounts by pass/fail for a single control.
type OutlierReport struct {
	ControlID       string          `json:"control_id"`
	PassingCount    int             `json:"passing_count"`
	FailingCount    int             `json:"failing_count"`
	FailingAccounts []AccountStatus `json:"failing_accounts"`
}

// Input configures the outlier analysis.
type Input struct {
	Consolidated consolidate.ConsolidatedReport
	Assessments  map[string]report.Assessment // account_id -> assessment
	ControlID    kernel.ControlID
}

// Analyze partitions accounts by pass/fail for the specified control.
// An account fails if any finding matches the control ID.
func Analyze(input Input) OutlierReport {
	result := OutlierReport{
		ControlID: string(input.ControlID),
	}

	for i := range input.Consolidated.Accounts {
		acct := &input.Consolidated.Accounts[i]
		assessment, ok := input.Assessments[acct.AccountID]
		if !ok {
			result.PassingCount++
			continue
		}

		dwellDays, failing := findControlDwell(&assessment, input.ControlID)
		if failing {
			result.FailingCount++
			result.FailingAccounts = append(result.FailingAccounts, AccountStatus{
				AccountID:   acct.AccountID,
				AccountName: acct.AccountName,
				DwellDays:   dwellDays,
			})
		} else {
			result.PassingCount++
		}
	}

	return result
}

// findControlDwell checks if any finding matches the control ID and returns dwell days.
func findControlDwell(a *report.Assessment, ctlID kernel.ControlID) (float64, bool) {
	for i := range a.Findings {
		f := &a.Findings[i]
		if f.ControlID == ctlID {
			return f.Evidence.UnsafeDurationHours / 24, true
		}
	}
	return 0, false
}
