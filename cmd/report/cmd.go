// Package report implements the 'stave report' command for executive
// report data export.
package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	HistoryDir    string
	SnapshotPath  string
	ControlsDir   string
	ChainsDir     string
	SLAFile       string
	TeamManifest  string
	Format        cmdutil.OutputFormat
	Title         string
	Period        string
	TeamBreakdown bool
}

// NewCmd constructs the report command.
func NewCmd() *cobra.Command {
	opts := &options{
		ControlsDir: "controls",
		ChainsDir:   "chains",
		Format:      cmdutil.FormatJSON,
		Title:       "Security Posture Report",
	}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate executive security posture report",
		Long: `Aggregate all assessment dimensions into a single structured
report document: posture score, findings summary, SLA compliance,
top findings, active chains, ATT&CK coverage, framework readiness,
team attribution, and executive summary.

Consumers render the report however needed — Jinja template,
Python script, Pandoc, or direct API consumption.

Inputs:
  --history PATH          History directory (required)
  --snapshot PATH         Snapshot to assess (required)
  --sla-profile-file PATH SLA policy
  --team-manifest PATH    Team manifest
  --format STRING         json (default) | markdown | html | csv
  --title STRING          Report title
  --period STRING         Reporting period label

Exit Codes:
  0   Report generated
  2   Invalid input
  4   Internal error`,
		Example: `  stave report --history ./history --snapshot latest.json
  stave report --history ./history --snapshot latest.json \
    --sla-profile-file sla.yaml --team-manifest teams.yaml \
    --format markdown > report.md`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "history directory (required)")
	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "snapshot to assess (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "controls directory (default: embedded catalog)")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "", "chains directory (default: embedded chains)")
	cmd.Flags().StringVar(&opts.SLAFile, "sla-profile-file", "", "SLA policy file")
	cmd.Flags().StringVar(&opts.TeamManifest, "team-manifest", "", "team manifest")
	cmd.Flags().VarP(&opts.Format, "format", "f", "output format: json | markdown | html | csv")
	cmd.Flags().StringVar(&opts.Title, "title", "Security Posture Report", "report title")
	cmd.Flags().StringVar(&opts.Period, "period", "", "reporting period label")
	cmd.Flags().BoolVar(&opts.TeamBreakdown, "team-breakdown", false, "Include per-team findings breakdown in report")

	cliflags.MustMarkRequired(cmd, "history")
	cliflags.MustMarkRequired(cmd, "snapshot")

	return cmd
}

func runReport(ctx context.Context, stdout io.Writer, opts *options) error {
	data, err := stave.BuildReport(ctx, stave.ReportInput{
		HistoryDir:   opts.HistoryDir,
		SnapshotPath: opts.SnapshotPath,
		ControlsDir:  opts.ControlsDir,
		ChainsDir:    opts.ChainsDir,
		SLAFile:      opts.SLAFile,
		TeamManifest: opts.TeamManifest,
		Title:        opts.Title,
		Period:       opts.Period,
		Format:       opts.Format.String(),
	}, time.Now().UTC())
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve the exit-4 message verbatim.
	}

	if _, writeErr := stdout.Write(data); writeErr != nil {
		return fmt.Errorf("write report: %w", writeErr)
	}
	return nil
}
