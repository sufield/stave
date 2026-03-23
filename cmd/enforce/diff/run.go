package diff

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/compose"

	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// config defines the parameters for comparing observation snapshots.
type config struct {
	ObservationsDir string
	Format          ui.OutputFormat
	Filter          asset.FilterOptions
	Quiet           bool
	Sanitizer       kernel.Sanitizer
	Stdout          io.Writer
	Stderr          io.Writer
}

// runner orchestrates the loading and comparison of observation snapshots.
type runner struct {
	LoadSnapshots compose.SnapshotLoader
}

// newRunner initializes a diff runner with the given snapshot loader.
func newRunner(load compose.SnapshotLoader) *runner {
	return &runner{LoadSnapshots: load}
}

// Run executes the diffing workflow: loading the two latest snapshots,
// calculating the delta, applying filters, and rendering the output.
func (r *runner) Run(ctx context.Context, cfg config) error {
	progress := ui.NewRuntime(cfg.Stdout, cfg.Stderr)
	progress.Quiet = cfg.Quiet
	stop := progress.BeginProgress("Computing observation delta")
	delta, err := r.computeDelta(ctx, cfg.ObservationsDir, cfg.Filter)
	stop()
	if err != nil {
		return err
	}

	delta = output.SanitizeObservationDelta(cfg.Sanitizer, delta)

	return writeOutput(cfg.Stdout, cfg.Format, cfg.Quiet, delta)
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
