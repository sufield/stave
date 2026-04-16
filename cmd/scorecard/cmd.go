// Package scorecard implements the 'stave scorecard' command for
// multi-framework compliance scorecard.
package scorecard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/observations"
	appsc "github.com/sufield/stave/internal/app/scorecard"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	Snapshot string
	Profiles []string
	Format   string
}

// NewCmd constructs the scorecard command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table"}

	cmd := &cobra.Command{
		Use:   "scorecard",
		Short: "Multi-framework compliance scorecard",
		Long: `Compute compliance readiness across multiple frameworks simultaneously.
Shows readiness percentage, critical findings, and trend per framework.

Exit Codes:
  0   Scorecard produced
  2   Invalid input`,
		Example: `  stave scorecard --snapshot snapshot.json
  stave scorecard --snapshot snapshot.json --profile hipaa --profile soc2 --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScorecard(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot JSON (required)")
	cmd.Flags().StringSliceVar(&opts.Profiles, "profile", nil, "framework profiles (repeatable; default: all built-in)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | markdown")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

var defaultFrameworks = []string{
	"hipaa", "nist_800_53_r5", "fedramp_moderate", "soc2",
	"pci_dss_v4.0", "cis_aws_v3.0", "iso_27001_2022",
}

func runScorecard(stdout io.Writer, opts *options) error {
	data, err := fsutil.ReadFileLimited(opts.Snapshot)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read snapshot: %w", err)}
	}

	// Try loading as assessment JSON first (has findings).
	var assessment struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if unmarshalErr := json.Unmarshal(data, &assessment); unmarshalErr != nil || len(assessment.Findings) == 0 {
		// Try as observation bundle — run assessment would be needed.
		// For now, scorecard works on assessment output, not raw snapshots.
		if _, loadErr := observations.ParseBundle(data); loadErr == nil {
			return &ui.UserError{Err: errors.New("--snapshot must be stave apply JSON output (assessment), not a raw observation snapshot")}
		}
		if unmarshalErr != nil {
			return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", unmarshalErr)}
		}
	}

	frameworks := opts.Profiles
	if len(frameworks) == 0 {
		frameworks = defaultFrameworks
	}

	report := appsc.Compute(assessment.Findings, frameworks)

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	case "markdown":
		return writeMarkdown(stdout, report)
	default:
		return writeTable(stdout, report)
	}
}

func writeTable(w io.Writer, r *appsc.Report) error {
	fmt.Fprintln(w, "COMPLIANCE SCORECARD")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-20s %10s %10s\n", "Framework", "Readiness", "Critical")
	fmt.Fprintf(w, "%-20s %10s %10s\n", strings.Repeat("-", 20), strings.Repeat("-", 10), strings.Repeat("-", 10))
	for i := range r.Frameworks {
		fw := &r.Frameworks[i]
		fmt.Fprintf(w, "%-20s %9.1f%% %10d\n", fw.Framework, fw.ReadinessPct, fw.CriticalFindings)
	}
	return nil
}

func writeMarkdown(w io.Writer, r *appsc.Report) error {
	fmt.Fprintln(w, "# Compliance Scorecard")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Framework | Readiness | Critical | Next Action |")
	fmt.Fprintln(w, "|-----------|-----------|----------|-------------|")
	for i := range r.Frameworks {
		fw := &r.Frameworks[i]
		fmt.Fprintf(w, "| %s | %.1f%% | %d | %s |\n",
			fw.Framework, fw.ReadinessPct, fw.CriticalFindings, fw.NextAction)
	}
	return nil
}
