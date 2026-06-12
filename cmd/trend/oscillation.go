package trend

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

func newOscillationCmd() *cobra.Command {
	var historyDir, files, format string
	var minOscillations int

	cmd := &cobra.Command{
		Use:   "oscillation",
		Short: "Classify violation oscillation patterns across assessment history",
		Long: `Classify control-asset pairs into oscillation patterns (chronic,
deploy-time, or random) by analyzing state transitions across a
sequence of assessment files.

Chronic patterns indicate persistent violations (>80%% failure rate).
Deploy-time patterns indicate violations that toggle with deployments.
Random patterns indicate no discernible oscillation pattern.

Inputs:
  --history            Directory of out.v0.1 assessment files
  --files              Comma-separated assessment files
  --min-oscillations   Minimum state transitions for deploy-time (default: 3)
  --format             Output format: table or json (default: table)

Exit Codes:
  0   Analysis complete
  2   Invalid input or insufficient data` + metadata.OfflineHelpSuffix,
		Example: `  stave trend oscillation --history ./assessments/
  stave trend oscillation --history ./assessments/ --min-oscillations 5
  stave trend oscillation --history ./assessments/ --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, warnings, err := stave.ClassifyOscillation(cmd.Context(), stave.TrendOscillationConfig{
				HistoryDir:      historyDir,
				Files:           files,
				MinOscillations: minOscillations,
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
				return fmt.Errorf("write oscillation output: %w", werr)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&historyDir, "history", "", "Directory of out.v0.1 assessment files")
	cmd.Flags().StringVar(&files, "files", "", "Comma-separated assessment files in chronological order")
	cmd.Flags().IntVar(&minOscillations, "min-oscillations", 3, "Minimum state transitions for deploy-time classification")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "Output format: table or json")

	return cmd
}
