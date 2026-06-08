// Package metrics implements the 'stave metrics' command for
// Prometheus text format metric export.
package metrics

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	HistoryDir string
	OutPath    string
}

// NewCmd constructs the metrics command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "metrics",
		Short: "Write Prometheus scrape file for node_exporter",
		Long: `Produce a stable Prometheus text format metrics file covering
posture score, findings by severity, SLA burn rates, chain
activations, and per-team metrics.

Designed for the node_exporter textfile collector. Run on a
schedule via cron to maintain continuous monitoring.

Inputs:
  --history DIR         Directory of assessment JSON files (required)
  --out PATH            Output .prom file path (required)

Exit Codes:
  0   Metrics written
  2   Invalid input`,
		Example: `  stave metrics --history ./history --out /var/lib/node_exporter/stave.prom
  stave metrics --history ./history --out stave.prom`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of assessment JSON files (required)")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "output .prom file path (required)")
	cliflags.MustMarkRequired(cmd, "history")
	cliflags.MustMarkRequired(cmd, "out")

	return cmd
}

func run(ctx context.Context, stdout io.Writer, opts *options) error {
	data, err := stave.RenderMetrics(ctx, opts.HistoryDir)
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped ("load history: ..."); preserve the message + exit code.
	}

	// Write to file or stdout. The fallback writer (when --out is
	// empty) is the command's stdout, not io.Discard — silently
	// dropping the report when no path was specified made the
	// command look successful while emitting nothing.
	if err := cmdutil.WriteTo(stdout, opts.OutPath, func(w io.Writer) error {
		_, werr := w.Write(data)
		return werr
	}); err != nil {
		return fmt.Errorf("write metrics: %w", err)
	}

	fmt.Fprintf(stdout, "Wrote metrics to %s\n", opts.OutPath)
	return nil
}
