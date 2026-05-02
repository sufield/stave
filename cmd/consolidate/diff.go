package consolidate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appconsolidate "github.com/sufield/stave/internal/app/consolidate"
	"github.com/sufield/stave/internal/app/outlieranalysis"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

// runDiff performs cross-account outlier analysis for a specific control.
func runDiff(ctx context.Context, stdout io.Writer, opts *options) error {
	if opts.DiffControl == "" {
		return errors.New("--diff-control is required")
	}

	// Load consolidation output (run consolidate first, or load from --history).
	if opts.HistoryDir == "" {
		return errors.New("--history is required with --diff-control (directory of per-account assessment files)")
	}

	consolidated, assessments, err := loadConsolidationData(ctx, opts.HistoryDir)
	if err != nil {
		return fmt.Errorf("load consolidation data: %w", err)
	}

	result := outlieranalysis.Analyze(outlieranalysis.Input{
		Consolidated: *consolidated,
		Assessments:  assessments,
		ControlID:    kernel.ControlID(opts.DiffControl),
	})

	if opts.Top > 0 && len(result.FailingAccounts) > opts.Top {
		result.FailingAccounts = result.FailingAccounts[:opts.Top]
	}

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		writeDiffTable(stdout, result)
		return nil
	}
}

func writeDiffTable(w io.Writer, r outlieranalysis.OutlierReport) {
	fmt.Fprintf(w, "OUTLIER ANALYSIS: %s\n", r.ControlID)
	fmt.Fprintln(w, strings.Repeat("\u2500", 60))
	fmt.Fprintf(w, "Passing: %d accounts  |  Failing: %d accounts\n\n", r.PassingCount, r.FailingCount)

	if len(r.FailingAccounts) == 0 {
		fmt.Fprintln(w, "No failing accounts.")
		return
	}

	fmt.Fprintln(w, "FAILING ACCOUNTS")
	fmt.Fprintf(w, "  %-16s  %-24s  %s\n", "Account ID", "Name", "Dwell")
	fmt.Fprintf(w, "  %-16s  %-24s  %s\n",
		strings.Repeat("\u2500", 16), strings.Repeat("\u2500", 24), strings.Repeat("\u2500", 6))
	for i := range r.FailingAccounts {
		a := &r.FailingAccounts[i]
		name := a.AccountName
		if name == "" {
			name = a.AccountID
		}
		fmt.Fprintf(w, "  %-16s  %-24s  %dd\n", a.AccountID, name, int(a.DwellDays))
	}
	fmt.Fprintln(w)
}

// loadConsolidationData builds a ConsolidatedReport and per-account assessments
// from a history directory containing per-account subdirectories.
func loadConsolidationData(ctx context.Context, dir string) (*appconsolidate.ConsolidatedReport, map[string]report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("read directory: %w", err)
	}

	loader := artifact.NewLoader()
	assessments := make(map[string]report.Assessment)
	var accounts []appconsolidate.AccountSummary

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		accountID := entry.Name()
		accountDir := filepath.Join(dir, accountID)
		files, readErr := os.ReadDir(accountDir)
		if readErr != nil {
			continue
		}

		// Load the latest assessment for this account.
		var latest *report.Assessment
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			path := filepath.Join(accountDir, f.Name())
			a, loadErr := loader.Evaluation(ctx, path)
			if loadErr != nil {
				continue
			}
			if latest == nil || a.Run.Now.After(latest.Run.Now) {
				latest = a
			}
		}

		if latest != nil {
			assessments[accountID] = *latest
			accounts = append(accounts, appconsolidate.AccountSummary{
				AccountID:   accountID,
				AccountName: accountID,
			})
		}
	}

	consolidated := &appconsolidate.ConsolidatedReport{
		AccountCount: len(accounts),
		Accounts:     accounts,
	}
	return consolidated, assessments, nil
}
