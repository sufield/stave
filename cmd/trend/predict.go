package trend

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

func newPredictCmd() *cobra.Command {
	var historyDir, files, profile, format string
	var targetReadiness float64
	var windowDays int

	cmd := &cobra.Command{
		Use:   "predict",
		Short: "Project compliance readiness achievement date",
		Long: `Predict estimates when a target compliance readiness percentage will
be achieved based on historical MTTR and current framework gaps.

Requires at least 2 assessment files to compute trends.

Inputs:
  --history            Directory of out.v0.1 assessment files
  --files              Comma-separated assessment files
  --profile            Compliance framework profile name
  --target-readiness   Target readiness percentage (default: 95)
  --window             Lookback window in days for MTTR computation (default: 90)
  --format             Output format: text or json (default: text)

Exit Codes:
  0   Prediction generated
  2   Invalid input or insufficient data
  4   Internal error` + metadata.OfflineHelpSuffix,
		Example: `  stave trend predict --history ./assessments/ --target-readiness 95
  stave trend predict --history ./assessments/ --profile pci_dss --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, warnings, err := stave.PredictReadiness(cmd.Context(), stave.TrendPredictConfig{
				HistoryDir:      historyDir,
				Files:           files,
				Profile:         profile,
				TargetReadiness: targetReadiness,
				WindowDays:      windowDays,
				Format:          format,
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
				return fmt.Errorf("write predict output: %w", werr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&historyDir, "history", "", "Directory of out.v0.1 assessment files")
	cmd.Flags().StringVar(&files, "files", "", "Comma-separated assessment files in chronological order")
	cmd.Flags().StringVar(&profile, "profile", "", "Compliance framework profile name")
	cmd.Flags().Float64Var(&targetReadiness, "target-readiness", 95, "Target readiness percentage")
	cmd.Flags().IntVar(&windowDays, "window", 90, "Lookback window in days for MTTR computation")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")

	return cmd
}
