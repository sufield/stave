package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	"github.com/sufield/stave/internal/app/auditbundle"
	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/metadata"
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

	// Load assessments in period.
	assessments, err := loadPeriodAssessments(ctx, opts.History, startDate, endDate)
	if err != nil {
		return fmt.Errorf("load assessments: %w", err)
	}

	if opts.DryRun {
		return writeDryRun(stdout, opts.Framework, periodLabel, assessments, opts.Exempt)
	}

	if opts.OutDir == "" {
		return errors.New("--out is required (output directory)")
	}

	// Build report JSON. Match the exemption-marshal pattern below:
	// a marshal failure on the audit summary would otherwise produce
	// an empty bundle artifact that downstream consumers would
	// silently treat as "no findings".
	reportJSON, err := json.MarshalIndent(map[string]any{
		"framework":   opts.Framework,
		"period":      periodLabel,
		"assessments": len(assessments),
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal audit report: %w", err)
	}

	// Build report markdown.
	reportMD := fmt.Appendf(nil, "# %s Audit Report — %s\n\nAssessments in period: %d\n",
		strings.ToUpper(opts.Framework), periodLabel, len(assessments))

	// Load exemptions if provided. Errors are fatal: an audit bundle
	// that silently omits the operator's --exempt input would falsely
	// represent compliance scope.
	var exemptJSON []byte
	if opts.Exempt != "" {
		af, loadErr := appexempt.Load(opts.Exempt)
		if loadErr != nil {
			return fmt.Errorf("load exemptions %q: %w", opts.Exempt, loadErr)
		}
		exemptJSON, err = json.MarshalIndent(af, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal exemptions: %w", err)
		}
	}

	pkg, err := auditbundle.Assemble(auditbundle.AssembleInput{
		Framework:      opts.Framework,
		Period:         periodLabel,
		OutputDir:      opts.OutDir,
		ReportJSON:     reportJSON,
		ReportMarkdown: reportMD,
		ExemptionsJSON: exemptJSON,
		GeneratedAt:    time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("assemble audit bundle: %w", err)
	}

	fmt.Fprintf(stdout, "Audit package written to %s (%d components)\n", opts.OutDir, len(pkg.Components))
	return nil
}

func parsePeriod(opts *auditOptions) (label string, start, end time.Time, err error) {
	if opts.Period != "" {
		parts := strings.SplitN(opts.Period, "-", 2)
		if len(parts) != 2 {
			return "", time.Time{}, time.Time{}, fmt.Errorf("invalid period %q (expected Q1-2026)", opts.Period)
		}
		quarter := strings.ToUpper(parts[0])
		year := parts[1]
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

func loadPeriodAssessments(ctx context.Context, dir string, start, end time.Time) ([]*report.Assessment, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read directory: %w", err)
	}

	loader := artifact.NewLoader()
	var assessments []*report.Assessment
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		a, loadErr := loader.Evaluation(ctx, path)
		if loadErr != nil {
			continue
		}
		if (a.Run.Now.Equal(start) || a.Run.Now.After(start)) &&
			(a.Run.Now.Equal(end) || a.Run.Now.Before(end)) {
			assessments = append(assessments, a)
		}
	}
	return assessments, nil
}

func writeDryRun(w io.Writer, framework, period string, assessments []*report.Assessment, exemptPath string) error {
	fmt.Fprintln(w, "AUDIT BUNDLE DRY RUN")
	fmt.Fprintf(w, "Framework: %s  |  Period: %s\n", strings.ToUpper(framework), period)
	fmt.Fprintln(w, strings.Repeat("\u2500", 55))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "WOULD COLLECT")
	fmt.Fprintf(w, "  \u2713 assessment-results.json  (%d assessments in period)\n", len(assessments))
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
