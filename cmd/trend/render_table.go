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

	// SLA compliance rate.
	if len(r.SLATrend) > 0 {
		fmt.Fprintf(w, "SLA COMPLIANCE RATE (last %d runs where SLA profile was active)\n", len(r.SLATrend))
		fmt.Fprintln(w, sep)
		for i := range r.SLATrend {
			m := &r.SLATrend[i]
			barWidth := 20
			filled := min(int(m.CompliancePercent/100*float64(barWidth)), barWidth)
			bar := strings.Repeat("#", filled) + strings.Repeat(".", barWidth-filled)
			fmt.Fprintf(w, "  Run %-3d (%s)  %s  %.0f%%\n",
				i+1, m.CapturedAt.Format("2006-01-02"), bar, m.CompliancePercent)
		}
		first := r.SLATrend[0].CompliancePercent
		last := r.SLATrend[len(r.SLATrend)-1].CompliancePercent
		netChange := last - first
		direction := "STABLE"
		if netChange > 1 {
			direction = "IMPROVING"
		} else if netChange < -1 {
			direction = "REGRESSING"
		}
		fmt.Fprintf(w, "\nNet change: %+.0f%%  Direction: %s\n\n", netChange, direction)
	}

	// Projection.
	if r.Projection != nil {
		fmt.Fprintln(w, "PROJECTION (linear — directional only)")
		fmt.Fprintln(w, sep)
		fmt.Fprintf(w, "  Current rate: %.1f%%   Target: %.1f%%\n",
			r.Runs[len(r.Runs)-1].ViolationRate*100, r.Projection.TargetRate*100)
		fmt.Fprintf(w, "  Estimated runs to target: ~%d runs at current pace\n", r.Projection.EstimatedRuns)
		fmt.Fprintf(w, "  Note: %s\n", r.Projection.Caveat)
	}

	// Per-team trends.
	if len(r.TeamTrends) > 0 && r.TeamSummary != nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "PER-TEAM POSTURE TREND")
		fmt.Fprintln(w, sep)
		ts := r.TeamSummary
		fmt.Fprintf(w, "  Teams tracked: %d  (improving: %d, stable: %d, regressing: %d)\n\n",
			ts.TeamsTracked, ts.TeamsImproving, ts.TeamsStable, ts.TeamsRegressing)

		fmt.Fprintf(w, "  %-16s %5s %6s  %-12s %7s %5s %4s %4s\n",
			"Team", "Score", "Delta", "Trajectory", "MTTR", "SLA%", "Open", "Crit")
		fmt.Fprintf(w, "  %-16s %5s %6s  %-12s %7s %5s %4s %4s\n",
			strings.Repeat("-", 16), "-----", "------", strings.Repeat("-", 12),
			"-------", "-----", "----", "----")
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			arrow := arrowFor(t.Trajectory)
			name := t.Name
			if name == "" {
				name = t.ID
			}
			if len(name) > 16 {
				name = name[:16]
			}
			fmt.Fprintf(w, "  %-16s %5.1f %+6.1f  %-12s %6.1fh %4.0f%% %4d %4d",
				name, t.PostureScore, t.ScoreDelta, t.Trajectory+" "+arrow, t.MTTRHours, t.SLACompPct, t.OpenFindings, t.CriticalOpen)
			if t.Trajectory == trajectoryRegressing {
				_, _ = fmt.Fprint(w, "  !!")
			}
			fmt.Fprintln(w)
		}
	}

	return nil
}

func arrowFor(trajectory string) string {
	switch trajectory {
	case trajectoryImproving:
		return "^"
	case trajectoryRegressing:
		return "v"
	default:
		return "-"
	}
}
