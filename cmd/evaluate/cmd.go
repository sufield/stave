// Package evaluate implements the stave evaluate command for running
// compliance profile evaluation against observation snapshots. Supports
// the HIPAA profile with compound risk detection, acknowledged exceptions,
// and text/JSON report output.
package evaluate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	ui "github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

// options holds the raw CLI flag values for the evaluate command.
type options struct {
	SnapshotPath string
	ProfileID    string
	Format       cmdutil.OutputFormat
	OutputPath   string
	// Now overrides exception expiry / acknowledgment date evaluation
	// for deterministic test fixtures and time-travel debugging. Empty
	// (the default) lets the command read time.Now() the first time it
	// resolves the exception evaluation point.
	Now string
}

// NewCmd constructs the evaluate command.
func NewCmd() *cobra.Command {
	opts := &options{
		Format: cmdutil.FormatText,
	}

	cmd := &cobra.Command{
		Use:     "evaluate",
		Aliases: []string{"eval"},
		Short:   "Evaluate a snapshot against a compliance profile",
		Long: `Evaluate runs all controls in a compliance profile against an observation
snapshot and produces a report with findings, remediation steps, and
compliance citations.

Exit Codes:
  0   All CRITICAL controls pass
  1   One or more CRITICAL controls fail
  2   Input or configuration error`,
		Example: `  stave evaluate --snapshot observations/snap.json --profile hipaa
  stave evaluate --snapshot snap.json --profile hipaa --format json --output report.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) (runErr error) {
			w, closer, err := resolveOutput(opts.OutputPath, cmd.OutOrStdout())
			if err != nil {
				return fmt.Errorf("open output: %w", err)
			}
			defer closer(&runErr)
			return run(cmd.Context(), w, opts)
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "Path to observation snapshot JSON (required)")
	cmd.Flags().StringVar(&opts.ProfileID, "profile", "", "Compliance profile ID (required)")
	cmd.Flags().VarP(&opts.Format, "format", "f", "Output format: text or json")
	cmd.Flags().StringVarP(&opts.OutputPath, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().StringVar(&opts.Now, "now", os.Getenv("STAVE_NOW"), "RFC3339 timestamp used as evaluation \"now\" for exception expiry (defaults to STAVE_NOW env, else wall clock)")

	cliflags.MustMarkRequired(cmd, "snapshot")
	cliflags.MustMarkRequired(cmd, "profile")

	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options) error {
	// ui.ParseOutputFormat normalizes the typed flag value; it stays
	// command-side because pkg/stave cannot import internal/cli/ui.
	format, fmtErr := ui.ParseOutputFormat(string(opts.Format))
	if fmtErr != nil {
		return fmt.Errorf("parse output format: %w", fmtErr)
	}

	out, failureMsg, err := stave.EvaluateSnapshot(ctx, opts.SnapshotPath, opts.ProfileID, string(format), opts.Now)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("evaluate"/"write report"); preserve exit 4.
	}

	if _, werr := w.Write(out); werr != nil {
		return fmt.Errorf("write report: %w", werr)
	}

	if failureMsg != "" {
		// Wrap with ui.ErrSecurityAuditFindings so the global ExitCode
		// routing maps this to ExitSecurity (=1).
		return fmt.Errorf("%w: %s", ui.ErrSecurityAuditFindings, failureMsg)
	}
	return nil
}

// ExitCode returns the exit code from an evaluate error, delegating to the
// global ui.ExitCode classifier so the evaluate command participates in
// the same exit-code map as every other command.
func ExitCode(err error) int {
	return ui.ExitCode(err)
}

// resolveOutput returns the destination writer and a closer that surfaces
// close errors instead of silently swallowing them. The closer accepts the
// run's outer error pointer; when the run succeeded but Close failed, the
// close error becomes the run's error so the caller does not exit 0 with a
// truncated file on disk.
func resolveOutput(path string, stdout io.Writer) (io.Writer, func(*error), error) {
	if path == "" {
		return stdout, func(*error) {}, nil
	}
	// SafeCreateFile rejects symlinks at the destination (resists
	// symlink-attack on a writable directory) and uses 0o600 perms.
	// Overwrite is allowed because re-running over the same output file
	// is a normal workflow.
	opts := fsutil.DefaultWriteOpts()
	opts.Overwrite = true
	f, err := fsutil.SafeCreateFile(fsutil.CleanUserPath(path), opts)
	if err != nil {
		return nil, nil, fmt.Errorf("create output file: %w", err)
	}
	return f, func(outErr *error) {
		closeErr := f.Close()
		// Two early-return cases: the caller did not pass an error slot
		// (outErr is nil → discard any close error), or close succeeded.
		if outErr == nil || closeErr == nil {
			return
		}
		// errors.Join keeps both diagnostics visible.
		if *outErr == nil {
			*outErr = closeErr
			return
		}
		*outErr = errors.Join(*outErr, closeErr)
	}, nil
}
