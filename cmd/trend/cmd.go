// Package trend implements the stave trend command for compliance posture
// trending across a sequence of assessment output files.
package trend

import (
	"github.com/spf13/cobra"
)

// NewCmd creates the trend command.
func NewCmd() *cobra.Command {
	opts := &trendOptions{
		Format:  "table",
		MinRuns: 2,
	}

	cmd := &cobra.Command{
		Use:   "trend",
		Short: "Analyze compliance posture trends across assessment runs",
		Long: `Reads a sequence of stave apply output files and computes posture
metrics including violation rate, MTTR, severity distribution,
attack stage trends, velocity, and improvement projection.

Requires at least 2 assessment files to produce a trend report.

Exit Codes:
  0   Trend report generated successfully
  2   Invalid input or insufficient data
  4   Internal error

Examples:
  stave trend --history ./assessments/
  stave trend --files run1.json,run2.json,run3.json --format json
  stave trend --history ./assessments/ --window 10 --out trend.json`,
		Example: `  stave trend --history ./assessments/
  stave trend --history ./assessments/ --format json --out trend.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTrend(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of out.v0.1 assessment files")
	cmd.Flags().StringVar(&opts.Files, "files", "", "comma-separated assessment files in chronological order")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | openmetrics")
	cmd.Flags().StringVar(&opts.Out, "out", "", "write output to file instead of stdout")
	cmd.Flags().IntVar(&opts.Window, "window", 0, "limit to most recent N assessments (0 = all)")
	cmd.Flags().IntVar(&opts.MinRuns, "min-runs", 2, "minimum assessment files required")
	cmd.Flags().StringVar(&opts.Compliance, "compliance", "", "comma-separated framework profiles for trajectory (hipaa,soc2,...)")
	cmd.Flags().StringVar(&opts.TeamManifest, "team-manifest", "", "path to team manifest YAML for per-team metrics")
	cmd.Flags().StringVar(&opts.Team, "team", "", "filter to specific team ID")
	cmd.Flags().BoolVar(&opts.RegressionOnly, "regression-only", false, "show only regressing teams")
	cmd.Flags().StringVar(&opts.Rollup, "rollup", "", "aggregate to hierarchy group ID")

	cmd.AddCommand(newPredictCmd())
	cmd.AddCommand(newForecastCmd())
	cmd.AddCommand(newOscillationCmd())

	return cmd
}

type trendOptions struct {
	HistoryDir     string
	Files          string
	Compliance     string
	Format         string
	Out            string
	Window         int
	MinRuns        int
	TeamManifest   string
	Team           string
	RegressionOnly bool
	Rollup         string
}
