package trendcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/app/trendpredict"
)

// PredictConfig parameterizes [PredictReadiness].
type PredictConfig struct {
	HistoryDir      string
	Files           string
	Profile         string
	TargetReadiness float64
	WindowDays      int
	Format          string
}

// PredictReadiness estimates when a target compliance readiness will be
// achieved (from historical MTTR + framework gaps) and renders it (text |
// json). Returns the rendered bytes + load warnings. An unknown format wraps
// [InputError] (exit 2); other failures stay plain (exit 4). It is the
// library entry point behind `stave trend predict`.
func PredictReadiness(ctx context.Context, cfg PredictConfig) ([]byte, []string, error) {
	if cfg.HistoryDir == "" && cfg.Files == "" {
		return nil, nil, errors.New("either --history or --files is required")
	}
	assessments, warnings, err := loadAssessments(ctx, cfg.HistoryDir, cfg.Files)
	if err != nil {
		return nil, warnings, err
	}
	if len(assessments) < 2 {
		return nil, warnings, fmt.Errorf("prediction requires at least 2 assessment files (found %d)", len(assessments))
	}

	now := time.Now().UTC()
	window := time.Duration(cfg.WindowDays) * 24 * time.Hour

	prediction := trendpredict.Predict(trendpredict.Input{
		Assessments:     assessments,
		Profile:         cfg.Profile,
		TargetReadiness: cfg.TargetReadiness,
		Window:          window,
		EvalTime:        now,
	})

	var buf bytes.Buffer
	if rErr := renderPredict(cfg.Format, &buf, prediction); rErr != nil {
		return nil, warnings, rErr
	}
	return buf.Bytes(), warnings, nil
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
