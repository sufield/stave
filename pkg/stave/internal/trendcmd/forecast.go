package trendcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/sla"
	"github.com/sufield/stave/internal/app/forecast"
	appscore "github.com/sufield/stave/internal/app/score"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/report"
)

// ForecastConfig parameterizes [ForecastPosture].
type ForecastConfig struct {
	HistoryDir     string
	Files          string
	SLAProfileFile string
	HorizonDays    int
	Format         string
}

// ForecastPosture projects the posture-score trajectory over a horizon (with
// optional per-severity SLA status) and renders it (table | json). Returns
// the rendered bytes + load warnings. An unknown format wraps [InputError]
// (exit 2); other failures stay plain (exit 4). It is the library entry point
// behind `stave trend forecast`.
func ForecastPosture(ctx context.Context, cfg ForecastConfig) ([]byte, []string, error) {
	if cfg.HistoryDir == "" && cfg.Files == "" {
		return nil, nil, errors.New("either --history or --files is required")
	}
	assessments, warnings, err := loadAssessments(ctx, cfg.HistoryDir, cfg.Files)
	if err != nil {
		return nil, warnings, err
	}
	if len(assessments) < 7 {
		return nil, warnings, fmt.Errorf("forecast requires at least 7 assessment files (found %d)", len(assessments))
	}

	slices.SortFunc(assessments, func(a, b *report.Assessment) int {
		return a.Run.EvalTime.Compare(b.Run.EvalTime)
	})

	scoreHistory := make([]float64, len(assessments))
	for i, a := range assessments {
		scoreHistory[i] = computeForecastScore(a)
	}

	mttrHistory := buildMTTRHistory(assessments)

	slaDeadlines := map[policy.Severity]float64{}
	if cfg.SLAProfileFile != "" {
		pol, slaErr := sla.LoadFromFile(cfg.SLAProfileFile)
		if slaErr != nil {
			return nil, warnings, fmt.Errorf("load sla profile: %w", slaErr)
		}
		for _, s := range []string{"critical", "high", "medium", "low"} {
			sev, _ := policy.ParseSeverity(s)
			slaDeadlines[sev] = pol.DeadlineHoursFor(s)
		}
	}

	result, err := forecast.Compute(forecast.Input{
		ScoreHistory: scoreHistory,
		HorizonDays:  cfg.HorizonDays,
		SLADeadlines: slaDeadlines,
		MTTRHistory:  mttrHistory,
	})
	if err != nil {
		return nil, warnings, fmt.Errorf("compute forecast: %w", err)
	}

	var buf bytes.Buffer
	if rErr := renderForecast(cfg.Format, &buf, result); rErr != nil {
		return nil, warnings, rErr
	}
	return buf.Bytes(), warnings, nil
}

func computeForecastScore(a *report.Assessment) float64 {
	if a.Summary.TotalAssets == 0 {
		return 100
	}
	return appscore.Compute(appscore.Input{
		Findings:      a.Findings,
		ChainFindings: a.ChainFindings,
		Weights:       appscore.DefaultWeights(),
		GeneratedAt:   a.Run.EvalTime,
	}).Score
}

func buildMTTRHistory(assessments []*report.Assessment) map[policy.Severity][]float64 {
	type fkey struct{ ctl, ast string }
	type window struct {
		sev    policy.Severity
		openAt time.Time
	}

	open := make(map[fkey]*window)
	resolvedDurations := make(map[policy.Severity][]float64)

	severities := []policy.Severity{policy.SeverityCritical, policy.SeverityHigh, policy.SeverityMedium, policy.SeverityLow}

	result := make(map[policy.Severity][]float64)
	for _, sev := range severities {
		result[sev] = make([]float64, 0, len(assessments))
	}

	for _, a := range assessments {
		currentKeys := make(map[fkey]struct{}, len(a.Findings))
		for i := range a.Findings {
			k := fkey{string(a.Findings[i].ControlID), string(a.Findings[i].AssetID)}
			currentKeys[k] = struct{}{}
			if _, exists := open[k]; !exists {
				sev, _ := policy.ParseSeverity(a.Findings[i].SeverityLabel())
				open[k] = &window{
					sev:    sev,
					openAt: a.Run.EvalTime,
				}
			}
		}
		for k, w := range open {
			if _, ok := currentKeys[k]; !ok {
				hours := a.Run.EvalTime.Sub(w.openAt).Hours()
				resolvedDurations[w.sev] = append(resolvedDurations[w.sev], hours)
				delete(open, k)
			}
		}

		for _, sev := range severities {
			durations := resolvedDurations[sev]
			if len(durations) == 0 {
				result[sev] = append(result[sev], 0.0)
			} else {
				var sum float64
				for _, d := range durations {
					sum += d
				}
				result[sev] = append(result[sev], sum/float64(len(durations)))
			}
		}
	}

	return result
}

func writeForecastTable(w io.Writer, r *forecast.Result) {
	fmt.Fprintln(w, "POSTURE SCORE FORECAST")
	fmt.Fprintf(w, "Horizon: %d days\n", r.Projected.HorizonDays)
	fmt.Fprintln(w, strings.Repeat("─", 55))
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
			strings.Repeat("─", 10), strings.Repeat("─", 14),
			strings.Repeat("─", 10), strings.Repeat("─", 10))
		for i := range r.SLAProj {
			s := &r.SLAProj[i]
			fmt.Fprintf(w, "  %-10s  %8.1fh       %8.0fh     %s %s\n",
				s.Severity, s.CurrentMTTR, s.Deadline, s.Status, s.StatusMarker())
		}
		fmt.Fprintln(w)
	}
}
