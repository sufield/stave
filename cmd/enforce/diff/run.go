package diff

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
)

// config defines the domain parameters for comparing observation snapshots.
type config struct {
	ObservationsDir string
	Format          ui.OutputFormat
	Filter          asset.FilterOptions
}

// runner orchestrates the loading and comparison of observation snapshots.
type runner struct {
	LoadSnapshots compose.SnapshotLoader
	Quiet         bool
	Sanitizer     kernel.Sanitizer
	Stdout        io.Writer
	Stderr        io.Writer
}

// newRunner initializes a diff runner with injected dependencies and global flags.
func newRunner(cmd *cobra.Command, load compose.SnapshotLoader) *runner {
	gf := cliflags.GetGlobalFlags(cmd)
	stdout := cmd.OutOrStdout()
	if !gf.TextOutputEnabled() {
		stdout = io.Discard
	}
	return &runner{
		LoadSnapshots: load,
		Quiet:         gf.Quiet,
		Sanitizer:     gf.GetSanitizer(),
		Stdout:        stdout,
		Stderr:        cmd.ErrOrStderr(),
	}
}

// Run executes the diffing workflow: loading the two latest snapshots,
// calculating the delta, applying filters, and rendering the output.
func (r *runner) Run(ctx context.Context, cfg config) error {
	progress := ui.NewRuntime(r.Stdout, r.Stderr)
	progress.Quiet = r.Quiet
	stop := progress.BeginProgress("Computing observation delta")
	defer stop()

	delta, err := r.computeDelta(ctx, cfg.ObservationsDir, cfg.Filter)
	if err != nil {
		return err
	}

	stop()

	delta = output.SanitizeObservationDelta(r.Sanitizer, delta)

	return writeOutput(r.Stdout, cfg.Format, r.Quiet, delta)
}

func (r *runner) computeDelta(ctx context.Context, dir string, filter asset.FilterOptions) (asset.ObservationDelta, error) {
	snapshots, err := r.LoadSnapshots(ctx, dir)
	if err != nil {
		return asset.ObservationDelta{}, fmt.Errorf("loading snapshots: %w", err)
	}
	if len(snapshots) < 2 {
		return asset.ObservationDelta{}, fmt.Errorf("need at least 2 snapshots in %s for diff", dir)
	}

	prev, curr, err := asset.LatestTwoSnapshots(snapshots)
	if err != nil {
		return asset.ObservationDelta{}, fmt.Errorf("select latest snapshots: %w", err)
	}
	return asset.ComputeObservationDelta(prev, curr).ApplyFilter(filter), nil
}
