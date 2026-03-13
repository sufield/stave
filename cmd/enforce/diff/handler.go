package diff

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/output"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// Config defines the parameters for comparing observation snapshots.
type Config struct {
	ObservationsDir string
	Format          ui.OutputFormat
	Filter          asset.FilterOptions
	Quiet           bool
	Sanitizer       kernel.Sanitizer
	Stdout          io.Writer
	Stderr          io.Writer
}

// Runner orchestrates the loading and comparison of observation snapshots.
type Runner struct {
	Provider *compose.Provider
}

// NewRunner initializes a diff runner with the provided dependency provider.
func NewRunner(p *compose.Provider) *Runner {
	return &Runner{Provider: p}
}

// Run executes the diffing workflow: loading the two latest snapshots,
// calculating the delta, applying filters, and rendering the output.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	progress := ui.NewRuntime(cfg.Stdout, cfg.Stderr)
	progress.Quiet = cfg.Quiet
	stop := progress.BeginProgress("Computing observation delta")
	delta, err := r.computeDelta(ctx, cfg.ObservationsDir, cfg.Filter)
	stop()
	if err != nil {
		return err
	}

	delta = output.SanitizeObservationDelta(cfg.Sanitizer, delta)

	if cfg.Quiet {
		return nil
	}
	if cfg.Format.IsJSON() {
		return jsonutil.WriteIndented(cfg.Stdout, delta)
	}
	return writeText(cfg.Stdout, delta)
}

func (r *Runner) computeDelta(ctx context.Context, dir string, filter asset.FilterOptions) (asset.ObservationDelta, error) {
	snapshots, err := r.Provider.LoadSnapshots(ctx, dir)
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

func writeText(w io.Writer, out asset.ObservationDelta) error {
	var err error
	writef := func(format string, args ...any) {
		if err != nil {
			return
		}
		_, err = fmt.Fprintf(w, format, args...)
	}

	writef("Observation delta: %s -> %s\n", out.FromCaptured.Format(time.RFC3339), out.ToCaptured.Format(time.RFC3339))
	writef("Summary: added=%d removed=%d modified=%d total=%d\n\n",
		out.Summary.Added(), out.Summary.Removed(), out.Summary.Modified(), out.Summary.Total())
	if err != nil {
		return err
	}
	if len(out.Changes) == 0 {
		writef("No asset changes detected.\n")
		return err
	}
	for _, c := range out.Changes {
		writef("- %s [%s]\n", c.AssetID, c.ChangeType)
		for _, p := range c.PropertyChanges {
			writef("  * %s: %v -> %v\n", p.Path, p.From, p.To)
		}
	}
	return err
}
