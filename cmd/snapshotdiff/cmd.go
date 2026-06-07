// Package snapshotdiff implements the 'stave snapshot-diff' command for
// structured observation snapshot comparison.
package snapshotdiff

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"errors"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/observations"
	appdiff "github.com/sufield/stave/internal/app/catalogdiff"
	"github.com/sufield/stave/internal/app/snapshotdiff"
	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	SnapshotBefore string
	SnapshotAfter  string
	Format         string
	Catalogs       bool
	CatalogBefore  string
	CatalogAfter   string
	NoPager        bool
}

// NewCmd constructs the diff command.
func NewCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	opts := &options{Format: "text"}

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two observation snapshots or control catalogs",
		Long: `Compare two observation snapshots or two control catalog versions.

Snapshot mode (default):
  Shows property changes, new/removed assets between two snapshots.

Catalog mode (--catalogs):
  Shows new/removed controls and severity changes between catalog versions.

Inputs:
  --snapshot-before PATH   Earlier snapshot JSON
  --snapshot-after PATH    Later snapshot JSON
  --catalogs               Compare control catalogs instead of snapshots
  --catalog-before PATH    Earlier catalog directory (with --catalogs)
  --catalog-after PATH     Later catalog directory (with --catalogs)

Exit Codes:
  0   Diff produced
  2   Invalid input`,
		Example: `  stave diff --snapshot-before snap1.json --snapshot-after snap2.json
  stave diff --catalogs --catalog-before ./controls-v1/ --catalog-after ./controls-v2/`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pageable := !opts.NoPager && opts.Format != "json"
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			var err error
			if opts.Catalogs {
				err = runCatalogDiff(cmd.Context(), pw, opts, newCtlRepo)
			} else {
				err = runSnapshotDiff(pw, opts)
			}
			if cerr := closePager(); cerr != nil && err == nil {
				err = cerr
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotBefore, "snapshot-before", "", "path to before snapshot JSON")
	cmd.Flags().StringVar(&opts.SnapshotAfter, "snapshot-after", "", "path to after snapshot JSON")
	cmd.Flags().BoolVar(&opts.Catalogs, "catalogs", false, "compare control catalogs instead of snapshots")
	cmd.Flags().StringVar(&opts.CatalogBefore, "catalog-before", "", "path to before catalog (with --catalogs)")
	cmd.Flags().StringVar(&opts.CatalogAfter, "catalog-after", "", "path to after catalog (with --catalogs)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")

	return cmd
}

func runCatalogDiff(ctx context.Context, stdout io.Writer, opts *options, newCtlRepo compose.CtlRepoFactory) error {
	if opts.CatalogBefore == "" || opts.CatalogAfter == "" {
		return &ui.UserError{Err: errors.New("--catalog-before and --catalog-after are required with --catalogs")}
	}

	repo, err := newCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}

	before, err := repo.LoadControls(ctx, opts.CatalogBefore)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load before catalog: %w", err)}
	}

	after, loadErr := repo.LoadControls(ctx, opts.CatalogAfter)
	if loadErr != nil {
		return &ui.UserError{Err: fmt.Errorf("load after catalog: %w", loadErr)}
	}

	delta := appdiff.Compute(before, after)

	renderer, rendErr := NewCatalogRenderer(opts.Format)
	if rendErr != nil {
		return rendErr
	}
	if err := renderer.Render(stdout, delta); err != nil {
		return fmt.Errorf("render catalog diff: %w", err)
	}
	return nil
}

func runSnapshotDiff(stdout io.Writer, opts *options) error {
	if opts.SnapshotBefore == "" || opts.SnapshotAfter == "" {
		return &ui.UserError{Err: errors.New("--snapshot-before and --snapshot-after are required")}
	}

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

	renderer, rendErr := NewSnapshotRenderer(opts.Format)
	if rendErr != nil {
		return rendErr
	}
	if err := renderer.Render(stdout, result); err != nil {
		return fmt.Errorf("render snapshot diff: %w", err)
	}
	return nil
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
