// Package coverage implements the 'stave coverage' command for
// observation field coverage gap analysis against control predicates.
package coverage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	SnapshotPath string
	ControlsDir  string
	Format       string
	OutFile      string
	NoPager      bool
}

// NewCmd constructs the coverage command.
func NewCmd() *cobra.Command {
	opts := &options{
		ControlsDir: "controls",
		Format:      "table",
	}

	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Analyze observation field coverage against control predicates",
		Long: `Analyze which controls can evaluate against a snapshot by checking
whether all fields referenced in control predicates are present in
the snapshot's asset properties.

Controls are classified as:
  EVALUABLE    All referenced fields present in snapshot
  INCOMPLETE   Some fields missing — INCOMPLETE verdict expected
  SILENT_RISK  Missing fields could produce false PASS verdicts
  NO_ASSETS    No assets of the required type in snapshot

Inputs:
  --snapshot PATH     Path to observation snapshot JSON (required)
  --controls PATH     Path to controls directory (default: controls)
  --format STRING     Output format: table (default) | json
  --out PATH          Write to file instead of stdout

Exit Codes:
  0   No silent risk controls
  2   Invalid input
  3   Silent risk controls detected`,
		Example: `  # Analyze coverage against snapshot
  stave coverage --snapshot snapshot.json

  # JSON output for automation
  stave coverage --snapshot snapshot.json --format json

  # Check before assessment
  stave coverage --snapshot snapshot.json && stave apply --snapshot snapshot.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Page only the human table to a terminal — never JSON, and never
			// when writing to a file (--out) or --no-pager is set.
			pageable := !opts.NoPager && opts.Format != "json" && opts.OutFile == ""
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			err := runCoverage(cmd.Context(), pw, opts)
			if cerr := closePager(); cerr != nil && err == nil {
				err = cerr
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "path to observation snapshot JSON (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "path to controls directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file instead of stdout")

	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

func runCoverage(ctx context.Context, stdout io.Writer, opts *options) error {
	// Validate the format up front (guard, not a render dispatch — the
	// rendering lives in pkg/stave — so this does not trip the
	// inline-format-switch lint).
	if opts.Format != "table" && opts.Format != "json" && opts.Format != "" {
		return &ui.UserError{Err: fmt.Errorf("unknown format %q (valid: table, json)", opts.Format)}
	}

	out, silentRisk, err := stave.AnalyzeFieldCoverage(ctx, opts.SnapshotPath, opts.ControlsDir, opts.Format, time.Now().UTC())
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("load controls"/"encode json"); preserve exit 4.
	}

	if writeErr := cmdutil.WriteTo(stdout, opts.OutFile, func(w io.Writer) error {
		_, e := w.Write(out)
		return e
	}); writeErr != nil {
		return fmt.Errorf("write coverage output: %w", writeErr)
	}

	if silentRisk {
		return ui.ErrViolationsFound
	}
	return nil
}
