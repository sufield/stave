package trend

import (
	"context"
	"fmt"
	"io"

	"github.com/sufield/stave/pkg/stave"
)

// runTrend delegates the load → compute → render pipeline to the facade,
// prints any per-file load warnings to stderr, and writes the rendered report
// to the pager writer w. w is the pager-wrapped stdout.
func runTrend(ctx context.Context, w, stderr io.Writer, opts *trendOptions) error {
	out, warnings, err := stave.TrendReport(ctx, stave.TrendConfig{
		HistoryDir:     opts.HistoryDir,
		Files:          opts.Files,
		Compliance:     opts.Compliance,
		Format:         opts.Format,
		Window:         opts.Window,
		MinRuns:        opts.MinRuns,
		TeamManifest:   opts.TeamManifest,
		Team:           opts.Team,
		RegressionOnly: opts.RegressionOnly,
		Rollup:         opts.Rollup,
	})
	for _, warn := range warnings {
		fmt.Fprintln(stderr, warn)
	}
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped; preserve exit 4.
	}

	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("write trend output: %w", err)
	}
	return nil
}
