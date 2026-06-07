// Package scorecard implements the 'stave scorecard' command for
// multi-framework compliance scorecard.
package scorecard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appsc "github.com/sufield/stave/internal/app/scorecard"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	Snapshot string
	Profiles []string
	Format   appcontracts.OutputFormat
}

// NewCmd constructs the scorecard command.
func NewCmd() *cobra.Command {
	opts := &options{Format: appcontracts.FormatTable}

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
	cmd.Flags().VarP(&opts.Format, "format", "f", "output format: table | json | markdown")
	cliflags.MustMarkRequired(cmd, "snapshot")

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
	unmarshalErr := json.Unmarshal(data, &assessment)
	if unmarshalErr != nil {
		// The earlier shape conflated "couldn't parse" with "parsed
		// but empty" by checking both conditions in the same branch.
		// Detect the raw-bundle case first (operator pointed
		// scorecard at the wrong file) and surface a clear hint;
		// otherwise the unmarshal failure is the actual cause.
		if _, loadErr := observations.ParseBundle(data); loadErr == nil {
			return &ui.UserError{Err: errors.New("--snapshot must be stave apply JSON output (assessment), not a raw observation snapshot")}
		}
		return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", unmarshalErr)}
	}
	if len(assessment.Findings) == 0 {
		// Zero findings is a legitimate input: every control passed.
		// Continue to the scorecard computation below — it correctly
		// reports a clean state. Surface the empty-input case as a
		// debug log so operators running with -v can confirm the
		// scorecard ran against an actual assessment, not a stub.
		slog.Debug("scorecard: assessment contained zero findings — treating as all-passing")
	}

	frameworks := opts.Profiles
	if len(frameworks) == 0 {
		frameworks = defaultFrameworks
	}

	report := appsc.Compute(assessment.Findings, frameworks)

	renderer, err := NewRenderer(opts.Format)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if err := renderer.Render(stdout, report); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
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
