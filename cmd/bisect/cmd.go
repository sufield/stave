package bisect

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	ControlsDir string
	ObsDir      string
	ControlID   string
	Mode        string
	Format      string
	EvalTime    string
	ResourceARN string
}

// NewCmd constructs the bisect command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "bisect",
		Short: "Find when a control was first violated",
		Long: `Bisect searches through timestamped snapshot history to find the exact
point in time when a control was first violated. Like git bisect for commits,
it binary-searches through a snapshot archive.

Modes:
  bisect (default)    Binary search — O(log N), finds the transition into the
                      current violation window. Fast for large archives.
  scan                Linear scan — O(N), finds ALL violation windows including
                      the earliest. Correct for non-monotonic histories.

Inputs:
  --controls, -i      Path to control definitions directory
  --observations, -o  Path to snapshot archive directory
  --control-id        ID of the single control to bisect (required)
  --mode              Search strategy: bisect or scan (default: bisect)
  --format, -f        Output format: text or json (default: text)
  --eval-time               Evaluation reference timestamp (RFC3339) for deterministic evaluation
  --resource          Scope to a specific resource ARN (optional)

Output:
  Text mode shows the transition point with a property delta between
  the last PASS and first VIOLATION snapshots. Timestamps use "between
  A and B" language — Stave operates on snapshots and cannot attribute
  changes to specific events within a window.

Exit Codes:
  0   No violation found in the archive
  2   Input error (missing flags, no snapshots)
  3   Violation window(s) found
  4   Internal error` + metadata.OfflineHelpSuffix,
		Example: `  # Find when a bucket became public
  stave bisect -i controls/s3 -o snapshots/ --control-id CTL.S3.PUBLIC.001

  # Scan for all violation windows over 12 months
  stave bisect -i controls/s3 -o snapshots/ --control-id CTL.S3.PUBLIC.001 --mode scan

  # Scope to a specific resource
  stave bisect -i controls/ -o snapshots/ --control-id CTL.S3.ENCRYPT.001 --resource arn:aws:s3:::prod-bucket`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if opts.ControlID == "" {
				return &ui.UserError{Err: errors.New("--control-id is required")}
			}

			out, err := stave.BisectControl(compose.CommandContext(cmd), stave.BisectInput{
				ControlsDir: opts.ControlsDir,
				ObsDir:      opts.ObsDir,
				ControlID:   opts.ControlID,
				Mode:        opts.Mode,
				Format:      opts.Format,
				EvalTime:    opts.EvalTime,
				ResourceARN: opts.ResourceARN,
				Logger:      cmdctx.LoggerFromCmd(cmd),
			})
			if err != nil {
				if errors.Is(err, stave.ErrInvalidInput) {
					return &ui.UserError{Err: err}
				}
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}

			if len(out.Stderr) > 0 {
				if _, werr := cmd.ErrOrStderr().Write(out.Stderr); werr != nil {
					return fmt.Errorf("write warnings: %w", werr)
				}
			}
			if _, werr := cmd.OutOrStdout().Write(out.Stdout); werr != nil {
				return fmt.Errorf("write output: %w", werr)
			}
			if out.HasViolations {
				return ui.ErrViolationsFound
			}
			return nil
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "Path to control definitions directory")
	cmd.Flags().StringVarP(&opts.ObsDir, "observations", "o", "observations", "Path to snapshot archive directory")
	cmd.Flags().StringVar(&opts.ControlID, "control-id", "", "Control ID to bisect (required)")
	cmd.Flags().StringVar(&opts.Mode, "mode", "bisect", "Search strategy: bisect or scan")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().StringVar(&opts.EvalTime, "eval-time", "", "Evaluation reference timestamp (RFC3339). Durations and temporal risk are measured against this time. Defaults to wall clock.")
	cmd.Flags().StringVar(&opts.ResourceARN, "resource", "", "Scope to a specific resource ARN")
	cliflags.MustMarkRequired(cmd, "control-id")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("mode", cliflags.CompleteFixed("bisect", "scan"))

	return cmd
}
