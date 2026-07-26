// Package snapshotdiff implements the 'stave snapshot compare' command for
// structured observation snapshot comparison.
package snapshotdiff

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	SnapshotBefore string
	SnapshotAfter  string
	Format         string
	NoPager        bool
}

// NewCmd constructs the diff command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "text"}

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two observation snapshots",
		Long: `Compare two observation snapshots and report property changes and
new/removed assets between them.

Inputs:
  --snapshot-before PATH   Earlier snapshot JSON
  --snapshot-after PATH    Later snapshot JSON

Exit Codes:
  0   Diff produced
  2   Invalid input`,
		Example:       `  stave snapshot compare --snapshot-before snap1.json --snapshot-after snap2.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Validate the format up front (guard, not a render dispatch —
			// the rendering lives in pkg/stave — so this does not trip the
			// inline-format-switch lint).
			if opts.Format != "json" && opts.Format != "table" && opts.Format != "" {
				return fmt.Errorf("unsupported format %q (expected: table | json)", opts.Format)
			}
			pageable := !opts.NoPager && opts.Format != "json"
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			err := runSnapshotDiff(pw, opts)
			if cerr := closePager(); cerr != nil && err == nil {
				err = cerr
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotBefore, "snapshot-before", "", "path to before snapshot JSON")
	cmd.Flags().StringVar(&opts.SnapshotAfter, "snapshot-after", "", "path to after snapshot JSON")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")

	return cmd
}

func runSnapshotDiff(stdout io.Writer, opts *options) error {
	if opts.SnapshotBefore == "" || opts.SnapshotAfter == "" {
		return &ui.UserError{Err: errors.New("--snapshot-before and --snapshot-after are required")}
	}

	out, err := stave.DiffSnapshotBundles(opts.SnapshotBefore, opts.SnapshotAfter, opts.Format)
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped; preserve the exit-4 message verbatim.
	}
	if _, err := stdout.Write(out); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}
