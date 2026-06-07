package trend

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/sla"
	"github.com/sufield/stave/internal/app/forecast"
	appscore "github.com/sufield/stave/internal/app/score"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/report"
	"github.com/sufield/stave/internal/platform/metadata"
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
			if historyDir == "" && files == "" {
				return errors.New("either --history or --files is required")
			}

			tOpts := &trendOptions{HistoryDir: historyDir, Files: files, MinRuns: 7}
			assessments, err := loadAssessments(cmd.Context(), cmd.ErrOrStderr(), tOpts)
			if err != nil {
				return err
			}
			if len(assessments) < 7 {
				return fmt.Errorf("forecast requires at least 7 assessment files (found %d)", len(assessments))
			}

			slices.SortFunc(assessments, func(a, b *report.Assessment) int {
				return a.Run.Now.Compare(b.Run.Now)
			})

			// Build daily score history.
			scoreHistory := make([]float64, len(assessments))
			for i, a := range assessments {
				scoreHistory[i] = computeForecastScore(a)
			}

			// Build MTTR history per severity.
			mttrHistory := buildMTTRHistory(assessments)

			// Load SLA deadlines.
			slaDeadlines := map[string]float64{}
			if slaProfileFile != "" {
				pol, slaErr := sla.LoadFromFile(slaProfileFile)
				if slaErr != nil {
					return fmt.Errorf("load sla profile: %w", slaErr)
				}
				for _, sev := range []string{"critical", "high", "medium", "low"} {
					slaDeadlines[sev] = pol.DeadlineHoursFor(sev)
				}
			}

			result, err := forecast.Compute(forecast.Input{
				ScoreHistory: scoreHistory,
				HorizonDays:  horizonDays,
				SLADeadlines: slaDeadlines,
				MTTRHistory:  mttrHistory,
			})
			if err != nil {
				return fmt.Errorf("compute forecast: %w", err)
			}

			renderer, rendErr := NewForecastRenderer(format)
			if rendErr != nil {
				return &ui.UserError{Err: rendErr}
			}
			return renderer.Render(cmd.OutOrStdout(), result)
		},
	}

	cmd.Flags().StringVar(&historyDir, "history", "", "directory of assessment JSON files")
	cmd.Flags().StringVar(&files, "files", "", "comma-separated assessment files")
	cmd.Flags().IntVar(&horizonDays, "horizon", 90, "forecast horizon in days")
	cmd.Flags().StringVar(&slaProfileFile, "sla-profile", "", "path to SLA policy YAML")
	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table | json")

	return cmd
}

func computeForecastScore(a *report.Assessment) float64 {
	if a.Summary.TotalAssets == 0 {
		return 100
	}
	return appscore.Compute(appscore.Input{
		Findings:      a.Findings,
		ChainFindings: a.ChainFindings,
		Weights:       appscore.DefaultWeights(),
		GeneratedAt:   a.Run.Now,
	}).Score
}

func buildMTTRHistory(assessments []*report.Assessment) map[string][]float64 {
	type fkey struct{ ctl, ast string }
	type window struct {
		sev    string
		openAt time.Time
	}

	open := make(map[fkey]*window)
	sevTotals := make(map[string][]float64)

	for _, a := range assessments {
		currentKeys := make(map[fkey]bool, len(a.Findings))
		for i := range a.Findings {
			k := fkey{string(a.Findings[i].ControlID), string(a.Findings[i].AssetID)}
			currentKeys[k] = true
			if _, exists := open[k]; !exists {
				open[k] = &window{
					sev:    a.Findings[i].SeverityLabel(),
					openAt: a.Run.Now,
				}
			}
		}
		for k, w := range open {
			if !currentKeys[k] {
				hours := a.Run.Now.Sub(w.openAt).Hours()
				sevTotals[w.sev] = append(sevTotals[w.sev], hours)
				delete(open, k)
			}
		}
	}

	return sevTotals
}

func writeForecastTable(w io.Writer, r *forecast.Result) {
	fmt.Fprintln(w, "POSTURE SCORE FORECAST")
	fmt.Fprintf(w, "Horizon: %d days\n", r.Projected.HorizonDays)
	fmt.Fprintln(w, strings.Repeat("\u2500", 55))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "SCORE TRAJECTORY")
	slopeDir := "stable"
	if r.Projected.ScoreSlope > 0.01 {
		slopeDir = "improving"
	} else if r.Projected.ScoreSlope < -0.01 {
		slopeDir = "declining"
	}
	fmt.Fprintf(w, "  Current score:      %.1f\n", r.Current.PostureScore)
	fmt.Fprintf(w, "  Score slope:        %+.2f points/day  (%s)\n", r.Projected.ScoreSlope, slopeDir)
	fmt.Fprintf(w, "  Projected (%dd):    %.1f\n", r.Projected.HorizonDays, r.Projected.PostureScore)
	fmt.Fprintln(w)

	if len(r.SLAProj) > 0 {
		fmt.Fprintln(w, "SLA STATUS")
		fmt.Fprintf(w, "  %-10s  %-14s  %-10s  %s\n", "Severity", "MTTR (current)", "SLA target", "Status")
		fmt.Fprintf(w, "  %-10s  %-14s  %-10s  %s\n",
			strings.Repeat("\u2500", 10), strings.Repeat("\u2500", 14),
			strings.Repeat("\u2500", 10), strings.Repeat("\u2500", 10))
		for i := range r.SLAProj {
			s := &r.SLAProj[i]
			fmt.Fprintf(w, "  %-10s  %8.1fh       %8.0fh     %s %s\n",
				s.Severity, s.CurrentMTTR, s.Deadline, s.Status, s.StatusMarker())
		}
		fmt.Fprintln(w)
	}
}
