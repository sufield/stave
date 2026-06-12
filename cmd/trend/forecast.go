package trend

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

func newForecastCmd() *cobra.Command {
	var historyDir, files, slaProfileFile, format string
	var horizonDays int

	cmd := &cobra.Command{
		Use:   "forecast",
		Short: "Project posture score trajectory with SLA breach warnings",
		Long: `Forecast computes a linear trend over daily posture scores and
projects the score forward over the specified horizon. When an
SLA profile is provided, annotates each severity with ON_TRACK,
AT_RISK, or BREACHING status based on MTTR trajectory.

Requires at least 7 assessment files for a meaningful trend.

Inputs:
  --history            Directory of out.v0.1 assessment files
  --files              Comma-separated assessment files
  --horizon            Forecast horizon in days (default: 90)
  --sla-profile        Path to SLA policy YAML (enables SLA status)
  --format             Output format: table or json (default: table)

Exit Codes:
  0   Forecast generated
  2   Invalid input or insufficient data` + metadata.OfflineHelpSuffix,
		Example: `  stave trend forecast --history ./assessments/ --horizon 90
  stave trend forecast --history ./assessments/ --sla-profile sla.yaml --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, warnings, err := stave.ForecastPosture(cmd.Context(), stave.TrendForecastConfig{
				HistoryDir:     historyDir,
				Files:          files,
				SLAProfileFile: slaProfileFile,
				HorizonDays:    horizonDays,
				Format:         format,
			})
			for _, warn := range warnings {
				fmt.Fprintln(cmd.ErrOrStderr(), warn)
			}
			if err != nil {
				if errors.Is(err, stave.ErrInvalidInput) {
					return &ui.UserError{Err: err}
				}
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			if _, werr := cmd.OutOrStdout().Write(out); werr != nil {
				return fmt.Errorf("write forecast output: %w", werr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&historyDir, "history", "", "directory of assessment JSON files")
	cmd.Flags().StringVar(&files, "files", "", "comma-separated assessment files")
	cmd.Flags().IntVar(&horizonDays, "horizon", 90, "forecast horizon in days")
	cmd.Flags().StringVar(&slaProfileFile, "sla-profile", "", "path to SLA policy YAML")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table | json")

	return cmd
}
