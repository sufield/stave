package trend

import (
	"fmt"
	"io"
	"strings"
)

func renderTrendTable(w io.Writer, r *TrendReport) error { //nolint:unparam // error return for format-dispatch consistency
	sep := strings.Repeat("-", 70)

	fmt.Fprintln(w, "POSTURE TREND REPORT")
	fmt.Fprintf(w, "Period: %s -> %s  |  Runs: %d\n\n",
		r.Period.Start.Format("2006-01-02"), r.Period.End.Format("2006-01-02"), r.Period.RunCount)

	// Violation rate over time.
	fmt.Fprintln(w, "VIOLATION RATE OVER TIME")
	fmt.Fprintln(w, sep)
	for i := range r.Runs {
		run := &r.Runs[i]
		barWidth := 20
		filled := 0
		if run.ViolationRate > 0 {
			filled = min(int(run.ViolationRate*float64(barWidth)), barWidth)
			if filled == 0 && run.ViolationCount > 0 {
				filled = 1
			}
		}
		bar := strings.Repeat("#", filled) + strings.Repeat(".", barWidth-filled)
		fmt.Fprintf(w, "  Run %-3d (%s)  %s  %d violations  (%.1f%%)\n",
			i+1, run.CapturedAt.Format("2006-01-02"), bar, run.ViolationCount, run.ViolationRate*100)
	}
	fmt.Fprintf(w, "\nDirection: %s\n\n", strings.ToUpper(r.Summary.Direction))

	// MTTR.
	if len(r.MTTR) > 0 {
		fmt.Fprintln(w, "MEAN TIME TO REMEDIATE (closed windows only)")
		fmt.Fprintln(w, sep)
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			if entry, ok := r.MTTR[sev]; ok {
				fmt.Fprintf(w, "  %-10s avg %5.1f days  (%d windows closed)\n", sev, entry.AvgDays, entry.WindowCount)
			}
		}
		fmt.Fprintln(w)
	}

	// Framework trajectory.
	if len(r.FrameworkTrends) > 0 {
		fmt.Fprintln(w, "FRAMEWORK COVERAGE TRAJECTORY")
		fmt.Fprintln(w, sep)
		for i := range r.FrameworkTrends {
			ft := &r.FrameworkTrends[i]
			var scoreParts []string
			showCount := 5
			start := 0
			if len(ft.Scores) > showCount {
				start = len(ft.Scores) - showCount
			}
			for _, s := range ft.Scores[start:] {
				scoreParts = append(scoreParts, fmt.Sprintf("%.0f%%", s*100))
			}
			arrow := ""
			switch ft.Direction {
			case "improving":
				arrow = "  ↑ improving"
			case "regressing":
				arrow = "  ↓ regressing"
			}
			fmt.Fprintf(w, "  %-12s %s%s\n", ft.Framework, strings.Join(scoreParts, " → "), arrow)
		}
		fmt.Fprintln(w)
	}

	// Velocity.
	fmt.Fprintln(w, "VELOCITY")
	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "  Net change: %.1f violations/run (last %d runs)\n", r.Velocity.AvgNetChange, r.Velocity.WindowRuns)
	fmt.Fprintf(w, "  Direction:  %s\n\n", strings.ToUpper(r.Velocity.Direction))

	// Projection.
	if r.Projection != nil {
		fmt.Fprintln(w, "PROJECTION (linear — directional only)")
		fmt.Fprintln(w, sep)
		fmt.Fprintf(w, "  Current rate: %.1f%%   Target: %.1f%%\n",
			r.Runs[len(r.Runs)-1].ViolationRate*100, r.Projection.TargetRate*100)
		fmt.Fprintf(w, "  Estimated runs to target: ~%d runs at current pace\n", r.Projection.EstimatedRuns)
		fmt.Fprintf(w, "  Note: %s\n", r.Projection.Caveat)
	}

	return nil
}
