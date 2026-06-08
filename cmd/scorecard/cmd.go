// Package scorecard implements the 'stave scorecard' command for
// multi-framework compliance scorecard.
package scorecard

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	Snapshot string
	Profiles []string
	Format   cmdutil.OutputFormat
}

// NewCmd constructs the scorecard command.
func NewCmd() *cobra.Command {
	opts := &options{Format: cmdutil.FormatTable}

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

func runScorecard(stdout io.Writer, opts *options) error {
	data, err := fsutil.ReadFileLimited(opts.Snapshot)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read snapshot: %w", err)}
	}

	out, err := stave.RenderScorecard(data, opts.Profiles, opts.Format.String())
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve the exit-4 render message verbatim.
	}
	if _, err := stdout.Write(out); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
