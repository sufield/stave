package bisect

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/metadata"
)

type options struct {
	ControlsDir string
	ObsDir      string
	ControlID   string
	Mode        string
	Format      string
	Now         string
	ResourceARN string
}

// NewCmd constructs the bisect command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "bisect",
		Short: "Find when a security invariant was first violated",
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
  --now               Override current time (RFC3339) for deterministic evaluation
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
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return runBisect(cmd, opts) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "Path to control definitions directory")
	cmd.Flags().StringVarP(&opts.ObsDir, "observations", "o", "observations", "Path to snapshot archive directory")
	cmd.Flags().StringVar(&opts.ControlID, "control-id", "", "Control ID to bisect (required)")
	cmd.Flags().StringVar(&opts.Mode, "mode", "bisect", "Search strategy: bisect or scan")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().StringVar(&opts.Now, "now", "", "Override current time (RFC3339)")
	cmd.Flags().StringVar(&opts.ResourceARN, "resource", "", "Scope to a specific resource ARN")
	_ = cmd.MarkFlagRequired("control-id")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("mode", cliflags.CompleteFixed("bisect", "scan"))

	return cmd
}

func parseMode(s string) (int, error) {
	switch s {
	case "bisect":
		return 0, nil // ModeBisect
	case "scan":
		return 1, nil // ModeScan
	default:
		return 0, fmt.Errorf("invalid --mode %q (supported: bisect, scan)", s)
	}
}

func (o *options) validate() error {
	if o.ControlID == "" {
		return errors.New("--control-id is required")
	}
	if _, err := parseMode(o.Mode); err != nil {
		return err
	}
	return nil
}
