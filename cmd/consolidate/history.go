package consolidate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/app/orgtrend"
	"github.com/sufield/stave/internal/core/report"
)

// runHistory loads per-account assessment history and produces an
// org-level trend report. The history directory structure is:
//
//	account-runs/
//	  account-123456/
//	    2026-01-01.json
//	    2026-01-02.json
//	  account-789012/
//	    2026-01-01.json
func runHistory(ctx context.Context, w io.Writer, opts *options) error {
	windowDur, err := parseWindowDuration(opts.Window)
	if err != nil {
		return fmt.Errorf("invalid --window: %w", err)
	}

	now := time.Now().UTC()
	if opts.Now != "" {
		now, err = time.Parse(time.RFC3339, opts.Now)
		if err != nil {
			return fmt.Errorf("parse --now: %w", err)
		}
	}

	accounts, err := loadAccountHistory(ctx, opts.HistoryDir)
	if err != nil {
		return fmt.Errorf("load history: %w", err)
	}
	if len(accounts) == 0 {
		return fmt.Errorf("no account directories found in %s", opts.HistoryDir)
	}

	trendReport := orgtrend.Compute(orgtrend.Input{
		Accounts: accounts,
		Window:   windowDur,
		Now:      now,
	})

	// Write output.
	return cmdutil.WriteTo(w, opts.OutPath, func(out io.Writer) error {
		switch opts.Format {
		case "json":
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(trendReport)
		case "markdown":
			writeHistoryMarkdown(out, trendReport)
		default:
			writeHistoryTable(out, trendReport)
		}
		return nil
	})
}

// loadAccountHistory walks the history directory, treating each
// subdirectory as an account with assessment JSON files.
func loadAccountHistory(ctx context.Context, dir string) ([]orgtrend.AccountTimeSeries, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	loader := artifact.NewLoader()
	var accounts []orgtrend.AccountTimeSeries

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		accountDir := filepath.Join(dir, entry.Name())
		files, readErr := os.ReadDir(accountDir)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", entry.Name(), readErr)
			continue
		}

		var runs []*report.Assessment
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			path := filepath.Join(accountDir, f.Name())
			a, loadErr := loader.Evaluation(ctx, path)
			if loadErr != nil {
				fmt.Fprintf(os.Stderr, "warning: skipping %s: %v\n", path, loadErr)
				continue
			}
			runs = append(runs, a)
		}

		if len(runs) > 0 {
			accounts = append(accounts, orgtrend.AccountTimeSeries{
				AccountID: entry.Name(),
				Runs:      runs,
			})
		}
	}
	return accounts, nil
}

func writeHistoryTable(w io.Writer, r *orgtrend.OrgTrendReport) {
	fmt.Fprintln(w, "ORG POSTURE TREND")
	fmt.Fprintf(w, "Accounts: %d  |  Window: %d days\n\n", r.AccountCount, r.WindowDays)

	fmt.Fprintln(w, "ORG AGGREGATE")
	fmt.Fprintf(w, "  Score today:  %.1f  (%+.1f vs %dd ago)\n", r.OrgScore, r.OrgDelta, r.WindowDays)
	fmt.Fprintf(w, "  Trajectory:   %s\n\n", r.OrgTrajectory)

	fmt.Fprintln(w, "ACCOUNT BREAKDOWN")
	fmt.Fprintf(w, "  %-20s %6s %7s  %-11s %8s\n",
		"Account", "Score", "Delta", "Trajectory", "Findings")
	fmt.Fprintf(w, "  %-20s %6s %7s  %-11s %8s\n",
		strings.Repeat("\u2500", 20), strings.Repeat("\u2500", 6),
		strings.Repeat("\u2500", 7), strings.Repeat("\u2500", 11),
		strings.Repeat("\u2500", 8))
	for i := range r.Accounts {
		a := &r.Accounts[i]
		marker := ""
		if a.Trajectory == orgtrend.TrajectoryRegressing {
			marker = " \u2190 !!"
		}
		name := a.AccountID
		if len(name) > 20 {
			name = name[:17] + "..."
		}
		fmt.Fprintf(w, "  %-20s %6.1f %+7.1f  %-11s %8d%s\n",
			name, a.Score, a.Delta, a.Trajectory, a.FindingCount, marker)
	}
	fmt.Fprintln(w)

	if len(r.RegressionDrivers) > 0 {
		fmt.Fprintln(w, "REGRESSION DRIVERS (accounts trending worse)")
		for i := range r.RegressionDrivers {
			d := &r.RegressionDrivers[i]
			fmt.Fprintf(w, "  %s: %s\n", d.AccountID, d.Description)
		}
		fmt.Fprintln(w)
	}

	if len(r.ChainActivations) > 0 {
		fmt.Fprintln(w, "CROSS-ACCOUNT CHAIN ACTIVATIONS")
		for i := range r.ChainActivations {
			ca := &r.ChainActivations[i]
			fmt.Fprintf(w, "  %-35s active in %d/%d accounts\n",
				ca.ChainID, ca.ActiveCount, ca.TotalCount)
		}
		fmt.Fprintln(w)
	}
}

func writeHistoryMarkdown(w io.Writer, r *orgtrend.OrgTrendReport) {
	fmt.Fprintln(w, "# Org Posture Trend")
	fmt.Fprintf(w, "\n**Accounts:** %d | **Window:** %d days | **Score:** %.1f (%+.1f) | **Trajectory:** %s\n\n",
		r.AccountCount, r.WindowDays, r.OrgScore, r.OrgDelta, r.OrgTrajectory)

	fmt.Fprintln(w, "| Account | Score | Delta | Trajectory | Findings |")
	fmt.Fprintln(w, "|---------|-------|-------|------------|----------|")
	for i := range r.Accounts {
		a := &r.Accounts[i]
		fmt.Fprintf(w, "| %s | %.1f | %+.1f | %s | %d |\n",
			a.AccountID, a.Score, a.Delta, a.Trajectory, a.FindingCount)
	}

	if len(r.RegressionDrivers) > 0 {
		fmt.Fprintln(w, "\n## Regression Drivers")
		for i := range r.RegressionDrivers {
			d := &r.RegressionDrivers[i]
			fmt.Fprintf(w, "- **%s:** %s\n", d.AccountID, d.Description)
		}
	}
}

func parseWindowDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if dayStr, ok := strings.CutSuffix(s, "d"); ok {
		var days int
		if _, err := fmt.Sscanf(dayStr, "%d", &days); err != nil {
			return 0, fmt.Errorf("parse days: %w", err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
