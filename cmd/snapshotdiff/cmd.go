// Package snapshotdiff implements the 'stave snapshot-diff' command for
// structured observation snapshot comparison.
package snapshotdiff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/app/snapshotdiff"
	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	SnapshotBefore string
	SnapshotAfter  string
	Format         string
}

// NewCmd constructs the snapshot-diff command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "text"}

	cmd := &cobra.Command{
		Use:   "snapshot-diff",
		Short: "Structured diff between two observation snapshots",
		Long: `Compare two observation snapshots and produce a structured diff
showing property changes, new assets, and removed assets.

Unlike git diff on raw JSON, snapshot-diff filters to meaningful
property changes and presents them asset-by-asset.

Inputs:
  --snapshot-before PATH   Path to the earlier snapshot JSON (required)
  --snapshot-after PATH    Path to the later snapshot JSON (required)

Outputs:
  stdout    Structured diff (text or JSON)

Exit Codes:
  0   Diff produced
  2   Invalid input`,
		Example: `  stave snapshot-diff \
    --snapshot-before snapshots/2026-02-13.json \
    --snapshot-after  snapshots/2026-02-14.json

  stave snapshot-diff \
    --snapshot-before snap1.json \
    --snapshot-after snap2.json \
    --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotBefore, "snapshot-before", "", "path to before snapshot JSON (required)")
	cmd.Flags().StringVar(&opts.SnapshotAfter, "snapshot-after", "", "path to after snapshot JSON (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	_ = cmd.MarkFlagRequired("snapshot-before")
	_ = cmd.MarkFlagRequired("snapshot-after")

	return cmd
}

func run(stdout io.Writer, opts *options) error {
	beforeSnaps, err := observations.LoadBundle(opts.SnapshotBefore)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load before snapshot: %w", err)}
	}
	if len(beforeSnaps) == 0 {
		return &ui.UserError{Err: fmt.Errorf("before snapshot %s has no snapshots", opts.SnapshotBefore)}
	}

	afterSnaps, err := observations.LoadBundle(opts.SnapshotAfter)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load after snapshot: %w", err)}
	}
	if len(afterSnaps) == 0 {
		return &ui.UserError{Err: fmt.Errorf("after snapshot %s has no snapshots", opts.SnapshotAfter)}
	}

	// Use the latest snapshot from each bundle.
	before := beforeSnaps[len(beforeSnaps)-1]
	after := afterSnaps[len(afterSnaps)-1]

	result := snapshotdiff.Diff(before, after)

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	default:
		return writeText(stdout, result)
	}
}

func writeText(w io.Writer, r *snapshotdiff.DiffResult) error {
	fmt.Fprintln(w, "SNAPSHOT DIFF")
	fmt.Fprintf(w, "Before: %s  (%d assets)\n",
		r.BeforeTime.Format("2006-01-02T15:04:05Z"), r.BeforeAssets)
	fmt.Fprintf(w, "After:  %s  (%d assets)\n\n",
		r.AfterTime.Format("2006-01-02T15:04:05Z"), r.AfterAssets)

	if len(r.PropertyChanges) > 0 {
		fmt.Fprintf(w, "PROPERTY CHANGES (%d)\n", len(r.PropertyChanges))
		fmt.Fprintln(w, strings.Repeat("\u2500", 55))

		currentAsset := ""
		for i := range r.PropertyChanges {
			c := &r.PropertyChanges[i]
			if string(c.AssetID) != currentAsset {
				currentAsset = string(c.AssetID)
				fmt.Fprintf(w, "  %s\n", c.AssetID)
			}
			fmt.Fprintf(w, "    %s:\n", c.Property)
			fmt.Fprintf(w, "      before: %v\n", c.Before)
			fmt.Fprintf(w, "      after:  %v\n", c.After)
		}
		fmt.Fprintln(w)
	}

	if len(r.NewAssets) > 0 {
		fmt.Fprintf(w, "NEW ASSETS (%d)\n", len(r.NewAssets))
		for i := range r.NewAssets {
			a := &r.NewAssets[i]
			fmt.Fprintf(w, "  %s\n", a.AssetID)
			fmt.Fprintf(w, "    asset_type: %s\n", a.AssetType)
		}
		fmt.Fprintln(w)
	}

	if len(r.RemovedAssets) > 0 {
		fmt.Fprintf(w, "REMOVED ASSETS (%d)\n", len(r.RemovedAssets))
		for i := range r.RemovedAssets {
			a := &r.RemovedAssets[i]
			fmt.Fprintf(w, "  %s  (%s)\n", a.AssetID, a.AssetType)
		}
		fmt.Fprintln(w)
	}

	if len(r.PropertyChanges) == 0 && len(r.NewAssets) == 0 && len(r.RemovedAssets) == 0 {
		fmt.Fprintln(w, "No differences found.")
	}

	return nil
}
