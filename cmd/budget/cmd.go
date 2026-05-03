// Package budget implements the 'stave budget' command for security
// SLA burn rate monitoring and deployment freeze gating.
package budget

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/adapters/sla"
	appbudget "github.com/sufield/stave/internal/app/budget"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

type options struct {
	HistoryDir     string
	OutputFile     string
	Period         string
	SLAProfile     string
	SLAProfileFile string
	FailBurnRate   float64
	FailSeverity   string
	Format         string
	Out            string
}

// NewCmd constructs the budget command.
func NewCmd() *cobra.Command {
	opts := &options{Period: "30d", Format: "table"}

	cmd := &cobra.Command{
		Use:   "budget",
		Short: "Security SLA burn rate monitoring and deployment gate",
		Long: `Compute security burn rate — the fraction of allowed unsafe
window consumed by open violations in a budget period. Used as
a deployment freeze gate and board-level risk metric.

Inputs:
  --history DIR       Directory of out.v0.1.json assessment files
  --output PATH       Single out.v0.1.json (current state only)
  --period DURATION   Budget period (default: 30d)
  --sla-profile NAME  SLA profile for deadline thresholds
  --sla-profile-file  Custom SLA profile YAML file
  --fail-on-burn-rate Percentage threshold to fail (exit 1)
  --fail-severity     Severities to gate (default: critical)
  --format FORMAT     table | json | openmetrics | markdown

Outputs:
  stdout              Burn rate report in selected format

Exit Codes:
  0   Burn rate within budget (or no gate configured)
  1   Burn rate exceeds --fail-on-burn-rate threshold
  2   Invalid input
  4   Internal error`,
		Example: `  # Current burn rate from assessment history
  stave budget --history ./evidence-archive/runs/

  # CI/CD gate — fail if critical burn rate > 80%
  stave budget --history ./assessments/ --fail-on-burn-rate 80

  # Board report
  stave budget --history ./assessments/ --format markdown`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBudget(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of out.v0.1.json files")
	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to single out.v0.1.json")
	cmd.Flags().StringVar(&opts.Period, "period", opts.Period, "budget period (e.g. 30d, 7d)")
	cmd.Flags().StringVar(&opts.SLAProfile, "sla-profile", "", "SLA profile name")
	cmd.Flags().StringVar(&opts.SLAProfileFile, "sla-profile-file", "", "custom SLA profile YAML")
	cmd.Flags().Float64Var(&opts.FailBurnRate, "fail-on-burn-rate", 0, "exit 1 if burn rate exceeds this percentage")
	cmd.Flags().StringVar(&opts.FailSeverity, "fail-severity", "critical", "severities to gate (comma-separated)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "output format: table | json | openmetrics | markdown")
	cmd.Flags().StringVar(&opts.Out, "out", "", "write output to file instead of stdout")

	return cmd
}

func runBudget(ctx context.Context, stdout io.Writer, opts *options) error {
	if opts.HistoryDir == "" && opts.OutputFile == "" {
		return errors.New("either --history or --output is required")
	}

	// Parse period.
	period, err := kernel.ParseDuration(opts.Period)
	if err != nil {
		return fmt.Errorf("parse period: %w", err)
	}

	// Load SLA profile.
	deadlines, profileID, err := loadDeadlines(opts)
	if err != nil {
		return err
	}

	// Load assessments.
	var assessments []*report.Assessment
	if opts.HistoryDir != "" {
		assessments, err = loadHistory(ctx, opts.HistoryDir)
	} else {
		var a *report.Assessment
		a, err = loadSingle(opts.OutputFile)
		if a != nil {
			assessments = []*report.Assessment{a}
		}
	}
	if err != nil {
		return err
	}
	if len(assessments) == 0 {
		return errors.New("no assessment data found")
	}

	// Sort by time, determine period bounds.
	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		return a.Run.Now.Compare(b.Run.Now)
	})
	periodEnd := assessments[len(assessments)-1].Run.Now
	periodStart := periodEnd.Add(-period)

	// Collect all findings from assessments in the period.
	latest := assessments[len(assessments)-1]

	result := appbudget.Compute(appbudget.Input{
		Findings:      latest.Findings,
		Period:        period,
		DeadlineHours: deadlines,
		PeriodStart:   periodStart,
		PeriodEnd:     periodEnd,
		ProfileID:     profileID,
	})

	// Evaluate gate if configured.
	if opts.FailBurnRate > 0 {
		sevs := strings.Split(opts.FailSeverity, ",")
		for i := range sevs {
			sevs[i] = strings.TrimSpace(sevs[i])
		}
		appbudget.EvaluateGate(&result, opts.FailBurnRate, sevs)
	}

	if writeErr := cmdutil.WriteTo(stdout, opts.Out, func(out io.Writer) error {
		switch opts.Format {
		case "json":
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		case "openmetrics":
			writeOpenMetrics(out, result)
		case "markdown":
			writeMarkdown(out, result)
		default:
			writeTable(out, result)
		}
		return nil
	}); writeErr != nil {
		return writeErr
	}

	// Exit code for gate. GateResult.ExitError centralises the
	// "passed → nil; failed → typed error" rule so this and
	// pkg/stave share a single source of truth.
	return result.Gate.ExitError()
}

func loadDeadlines(opts *options) (map[string]float64, string, error) {
	var pol *sla.Policy
	var err error
	if opts.SLAProfileFile != "" {
		pol, err = sla.LoadFromFile(opts.SLAProfileFile)
	} else if opts.SLAProfile != "" {
		pol, err = sla.LoadEmbedded(opts.SLAProfile)
	} else {
		pol, err = sla.LoadEmbedded("default")
	}
	if err != nil {
		return nil, "", fmt.Errorf("load SLA profile: %w", err)
	}
	return map[string]float64{
		"critical": pol.DeadlineHoursFor("critical"),
		"high":     pol.DeadlineHoursFor("high"),
		"medium":   pol.DeadlineHoursFor("medium"),
		"low":      pol.DeadlineHoursFor("low"),
	}, pol.ID, nil
}

func loadHistory(ctx context.Context, dir string) ([]*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}
	loader := artifact.NewLoader()
	var result []*report.Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		a, loadErr := loader.Evaluation(ctx, filepath.Join(dir, entry.Name()))
		if loadErr != nil {
			continue
		}
		result = append(result, a)
	}
	return result, nil
}

func loadSingle(path string) (*report.Assessment, error) {
	data, err := os.ReadFile(path) //nolint:gosec // user-specified path
	if err != nil {
		return nil, fmt.Errorf("read assessment: %w", err)
	}
	var a report.Assessment
	if jsonErr := json.Unmarshal(data, &a); jsonErr != nil {
		return nil, fmt.Errorf("parse assessment: %w", jsonErr)
	}
	return &a, nil
}

// --- Output renderers ---

func writeTable(w io.Writer, r appbudget.Report) {
	fmt.Fprintln(w, "SECURITY BURN RATE REPORT")
	fmt.Fprintf(w, "Period: %s \u2192 %s (%d days)  |  SLA Profile: %s\n\n",
		r.Period.From.Format("2006-01-02"), r.Period.To.Format("2006-01-02"),
		r.Period.DurationDays, r.SLAProfile)

	fmt.Fprintln(w, "BURN RATE BY SEVERITY")
	fmt.Fprintln(w, strings.Repeat("\u2500", 72))
	fmt.Fprintf(w, "%-10s %8s %10s %10s %10s   %-15s %s\n",
		"Severity", "Budget", "Consumed", "Remaining", "Burn Rate", "Bar", "Status")
	fmt.Fprintln(w, strings.Repeat("\u2500", 72))

	for i := range r.BurnRates {
		br := &r.BurnRates[i]
		bar := burnBar(br.BurnRatePercent)
		fmt.Fprintf(w, "%-10s %7.0fh %9.0fh %9.0fh %9.1f%%   %s  %s\n",
			strings.ToUpper(br.SeverityLabel()), br.AllowedHours, br.ConsumedHours,
			br.RemainingHours, br.BurnRatePercent, bar, br.StatusLabel())
	}

	// Velocity section.
	for i := range r.BurnRates {
		br := &r.BurnRates[i]
		if len(br.WeeklyConsumption) > 0 && br.IsCritical() {
			fmt.Fprintf(w, "\nVELOCITY (%s)\n", strings.ToUpper(br.SeverityLabel()))
			for wi, wh := range br.WeeklyConsumption {
				wbar := strings.Repeat("\u2588", int(math.Min(wh, 40)))
				fmt.Fprintf(w, "  Week %d  %5.0fh  %s\n", wi+1, wh, wbar)
			}
		}
	}

	if r.Gate != nil {
		fmt.Fprintf(w, "\nDEPLOYMENT GATE: %s  (%s)\n", r.Gate.PassLabel(), r.Gate.Reason)
	}
}

func writeOpenMetrics(w io.Writer, r appbudget.Report) {
	tsMs := r.GeneratedAt.UnixMilli()

	fmt.Fprintln(w, "# HELP stave_security_burn_rate Security SLA burn rate (0-1)")
	fmt.Fprintln(w, "# TYPE stave_security_burn_rate gauge")
	for i := range r.BurnRates {
		br := &r.BurnRates[i]
		fmt.Fprintf(w, "stave_security_burn_rate{severity=%q,profile=%q} %.3f %d\n",
			br.SeverityLabel(), r.SLAProfile, br.BurnRateRatio(), tsMs)
	}

	fmt.Fprintln(w, "# HELP stave_security_budget_hours_remaining Budget hours remaining this period")
	fmt.Fprintln(w, "# TYPE stave_security_budget_hours_remaining gauge")
	for i := range r.BurnRates {
		br := &r.BurnRates[i]
		fmt.Fprintf(w, "stave_security_budget_hours_remaining{severity=%q} %.1f %d\n",
			br.SeverityLabel(), br.RemainingHours, tsMs)
	}

	fmt.Fprintln(w, "# HELP stave_security_budget_exhausted 1 if budget exhausted (burn rate >= 1.0)")
	fmt.Fprintln(w, "# TYPE stave_security_budget_exhausted gauge")
	for i := range r.BurnRates {
		br := &r.BurnRates[i]
		exhausted := 0
		if br.IsExhausted() {
			exhausted = 1
		}
		fmt.Fprintf(w, "stave_security_budget_exhausted{severity=%q} %d %d\n",
			br.SeverityLabel(), exhausted, tsMs)
	}

	fmt.Fprintln(w, "# EOF")
}

func writeMarkdown(w io.Writer, r appbudget.Report) {
	fmt.Fprintf(w, "# Security Budget Report\n\n")
	fmt.Fprintf(w, "**Period:** %s to %s (%d days)  \n",
		r.Period.From.Format("January 2, 2006"), r.Period.To.Format("January 2, 2006"),
		r.Period.DurationDays)
	fmt.Fprintf(w, "**SLA Profile:** %s  \n\n", r.SLAProfile)

	fmt.Fprintln(w, "## Burn Rate by Severity")
	fmt.Fprintln(w, "| Severity | Budget | Consumed | Burn Rate | Status |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for i := range r.BurnRates {
		br := &r.BurnRates[i]
		fmt.Fprintf(w, "| %s | %.0fh | %.0fh | %.1f%% | %s |\n",
			strings.ToUpper(br.SeverityLabel()[:1])+br.SeverityLabel()[1:], br.AllowedHours, br.ConsumedHours,
			br.BurnRatePercent, br.StatusLabel())
	}

	if r.Gate != nil {
		result := "No deployment freezes triggered."
		if !r.Gate.IsPassed() {
			result = "**DEPLOYMENT FREEZE TRIGGERED.** " + r.Gate.Reason
		}
		fmt.Fprintf(w, "\n## Deployment Gate\n\n%s\n", result)
	}

	fmt.Fprintln(w, "\n---")
	fmt.Fprintln(w, "*Generated from local assessment archive. No cloud API calls made.*")
}

func burnBar(pct float64) string {
	filled := int(math.Min(pct/100*15, 15))
	empty := 15 - filled
	return strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", max(empty, 0))
}
