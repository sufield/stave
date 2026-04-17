package trend

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/trendpredict"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/util/jsonutil"
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
			if historyDir == "" && files == "" {
				return errors.New("either --history or --files is required")
			}

			tOpts := &trendOptions{HistoryDir: historyDir, Files: files, MinRuns: 2}
			assessments, err := loadAssessments(cmd.Context(), tOpts)
			if err != nil {
				return err
			}
			if len(assessments) < 2 {
				return fmt.Errorf("prediction requires at least 2 assessment files (found %d)", len(assessments))
			}

			now := time.Now().UTC()
			window := time.Duration(windowDays) * 24 * time.Hour

			prediction := trendpredict.Predict(trendpredict.Input{
				Assessments:     assessments,
				Profile:         profile,
				TargetReadiness: targetReadiness,
				Window:          window,
				Now:             now,
			})

			stdout := cmd.OutOrStdout()
			if format == "json" {
				return jsonutil.WriteIndented(stdout, prediction)
			}
			return renderPredictText(stdout, prediction)
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

func renderPredictText(w io.Writer, p *trendpredict.Prediction) error {
	fmt.Fprintf(w, "Profile:           %s\n", p.Profile)
	fmt.Fprintf(w, "Current readiness: %.1f%%\n", p.CurrentReadiness)
	fmt.Fprintf(w, "Target readiness:  %.1f%%\n", p.TargetReadiness)
	fmt.Fprintf(w, "\n")

	if !p.ProjectedDate.IsZero() {
		fmt.Fprintf(w, "Projected date:    %s\n", p.ProjectedDate.Format("2006-01-02"))
		fmt.Fprintf(w, "Optimistic:        %s\n", p.OptimisticDate.Format("2006-01-02"))
		fmt.Fprintf(w, "Pessimistic:       %s\n", p.PessimisticDate.Format("2006-01-02"))
	} else {
		fmt.Fprintf(w, "Insufficient data for projection.\n")
	}

	if len(p.Accelerators) > 0 {
		fmt.Fprintf(w, "\nAccelerators:\n")
		for _, a := range p.Accelerators {
			fmt.Fprintf(w, "  - %s (saves ~%d days)\n", a.Description, a.DaysSaved)
			for _, id := range a.ControlIDs {
				fmt.Fprintf(w, "    %s\n", id)
			}
		}
	}
	return nil
}
