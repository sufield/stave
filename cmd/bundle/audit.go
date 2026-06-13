package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

type auditOptions struct {
	Framework string
	Period    string
	From      string
	To        string
	History   string
	Exempt    string
	OutDir    string
	DryRun    bool
	Format    string
}

func newAuditCmd() *cobra.Command {
	opts := &auditOptions{Format: "table"}

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Assemble a compliance-period evidence package",
		Long: `Package all evidence components for a specific compliance framework
and time period into a named directory with a SHA-256 manifest.

Components: assessment results, executive report, continuity
attestation, remediation trend, and exemption register.

Inputs:
  --framework        Compliance framework (hipaa, soc2, fedramp, pci_dss)
  --period           Period shorthand (Q1-2026, Q4-2025)
  --from / --to      Explicit date range (ISO 8601)
  --history          Directory of assessment JSON files
  --exempt           Path to acknowledgments YAML (optional)
  --out              Output directory (created if not exists)
  --dry-run          Show what would be collected without writing

Exit Codes:
  0   Package assembled
  2   Invalid input` + metadata.OfflineHelpSuffix,
		Example: `  stave bundle audit --framework hipaa --period Q1-2026 --history ./assessments/ --out ./audit/
  stave bundle audit --framework soc2 --from 2025-01-01 --to 2025-12-31 --history ./assessments/
  stave bundle audit --framework hipaa --period Q1-2026 --history ./assessments/ --dry-run`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAudit(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Framework, "framework", "", "compliance framework (required)")
	cmd.Flags().StringVar(&opts.Period, "period", "", "period shorthand (e.g. Q1-2026)")
	cmd.Flags().StringVar(&opts.From, "from", "", "period start date (ISO 8601)")
	cmd.Flags().StringVar(&opts.To, "to", "", "period end date (ISO 8601)")
	cmd.Flags().StringVar(&opts.History, "history", "", "directory of assessment JSON files (required)")
	cmd.Flags().StringVar(&opts.Exempt, "exempt", "", "path to acknowledgments YAML")
	cmd.Flags().StringVar(&opts.OutDir, "out", "", "output directory (required unless --dry-run)")
	cmd.Flags().BoolVar(&opts.DryRun, "dry-run", false, "show what would be collected")
	_ = cmd.MarkFlagRequired("framework")
	_ = cmd.MarkFlagRequired("history")

	return cmd
}

func runAudit(ctx context.Context, stdout io.Writer, opts *auditOptions) error {
	periodLabel, startDate, endDate, err := parsePeriod(opts)
	if err != nil {
		return err
	}

	res, err := stave.AssembleAuditBundle(ctx, stave.AuditBundleInput{
		Framework:  opts.Framework,
		Period:     periodLabel,
		Start:      startDate,
		End:        endDate,
		HistoryDir: opts.History,
		ExemptPath: opts.Exempt,
		OutDir:     opts.OutDir,
		DryRun:     opts.DryRun,
	})
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped ("load assessments"/"assemble audit bundle"); preserve exit codes.
	}

	if opts.DryRun {
		return writeDryRun(stdout, opts.Framework, periodLabel, res.AssessmentCount, opts.Exempt)
	}

	fmt.Fprintf(stdout, "Audit package written to %s (%d components)\n", opts.OutDir, res.ComponentCount)
	return nil
}

func parsePeriod(opts *auditOptions) (label string, start, end time.Time, err error) {
	if opts.Period != "" {
		quarterRaw, year, ok := strings.Cut(opts.Period, "-")
		if !ok {
			return "", time.Time{}, time.Time{}, fmt.Errorf("invalid period %q (expected Q1-2026)", opts.Period)
		}
		quarter := strings.ToUpper(quarterRaw)
		var yearInt int
		if _, scanErr := fmt.Sscanf(year, "%d", &yearInt); scanErr != nil {
			return "", time.Time{}, time.Time{}, fmt.Errorf("invalid year in period %q", opts.Period)
		}
		switch quarter {
		case "Q1":
			start = time.Date(yearInt, 1, 1, 0, 0, 0, 0, time.UTC)
			end = time.Date(yearInt, 3, 31, 23, 59, 59, 0, time.UTC)
		case "Q2":
			start = time.Date(yearInt, 4, 1, 0, 0, 0, 0, time.UTC)
			end = time.Date(yearInt, 6, 30, 23, 59, 59, 0, time.UTC)
		case "Q3":
			start = time.Date(yearInt, 7, 1, 0, 0, 0, 0, time.UTC)
			end = time.Date(yearInt, 9, 30, 23, 59, 59, 0, time.UTC)
		case "Q4":
			start = time.Date(yearInt, 10, 1, 0, 0, 0, 0, time.UTC)
			end = time.Date(yearInt, 12, 31, 23, 59, 59, 0, time.UTC)
		default:
			return "", time.Time{}, time.Time{}, fmt.Errorf("invalid quarter %q (expected Q1-Q4)", quarter)
		}
		return opts.Period, start, end, nil
	}

	if opts.From != "" && opts.To != "" {
		start, err = time.Parse("2006-01-02", opts.From)
		if err != nil {
			return "", time.Time{}, time.Time{}, fmt.Errorf("parse --from: %w", err)
		}
		end, err = time.Parse("2006-01-02", opts.To)
		if err != nil {
			return "", time.Time{}, time.Time{}, fmt.Errorf("parse --to: %w", err)
		}
		return fmt.Sprintf("%s to %s", opts.From, opts.To), start, end, nil
	}

	return "", time.Time{}, time.Time{}, errors.New("either --period or --from/--to is required")
}

func writeDryRun(w io.Writer, framework, period string, assessmentCount int, exemptPath string) error {
	fmt.Fprintln(w, "AUDIT BUNDLE DRY RUN")
	fmt.Fprintf(w, "Framework: %s  |  Period: %s\n", strings.ToUpper(framework), period)
	fmt.Fprintln(w, strings.Repeat("\u2500", 55))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "WOULD COLLECT")
	fmt.Fprintf(w, "  \u2713 assessment-results.json  (%d assessments in period)\n", assessmentCount)
	fmt.Fprintln(w, "  \u2713 assessment-report.md")
	fmt.Fprintln(w, "  \u2713 continuity.json")
	fmt.Fprintln(w, "  \u2713 trend.json")
	if exemptPath != "" {
		fmt.Fprintf(w, "  \u2713 exemptions.json          (from %s)\n", exemptPath)
	} else {
		fmt.Fprintln(w, "  \u2014 exemptions.json          (no --exempt provided)")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run without --dry-run to generate the package.")
	return nil
}
