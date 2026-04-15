package trend

import (
	"fmt"
	"io"
)

func renderTrendOpenMetrics(w io.Writer, r *TrendReport) error { //nolint:unparam // error return for format-dispatch consistency
	if len(r.Runs) == 0 {
		fmt.Fprintln(w, "# EOF")
		return nil
	}

	latest := &r.Runs[len(r.Runs)-1]
	tsMs := latest.CapturedAt.UnixMilli()

	// violations_total by severity
	fmt.Fprintln(w, "# HELP stave_violations_total Current violation count by severity")
	fmt.Fprintln(w, "# TYPE stave_violations_total gauge")
	for sev, count := range latest.BySeverity {
		fmt.Fprintf(w, "stave_violations_total{severity=%q} %d %d\n", sev, count, tsMs)
	}
	fmt.Fprintln(w)

	// violation_rate
	fmt.Fprintln(w, "# HELP stave_violation_rate Current violation rate")
	fmt.Fprintln(w, "# TYPE stave_violation_rate gauge")
	fmt.Fprintf(w, "stave_violation_rate %g %d\n\n", latest.ViolationRate, tsMs)

	// mttr_days (omitted when no closed windows)
	if len(r.MTTR) > 0 {
		fmt.Fprintln(w, "# HELP stave_mttr_days Mean time to remediate by severity")
		fmt.Fprintln(w, "# TYPE stave_mttr_days gauge")
		for sev, entry := range r.MTTR {
			fmt.Fprintf(w, "stave_mttr_days{severity=%q} %g %d\n", sev, entry.AvgDays, tsMs)
		}
		fmt.Fprintln(w)
	}

	// framework_coverage (only when compliance specified)
	if len(r.FrameworkTrends) > 0 {
		fmt.Fprintln(w, "# HELP stave_framework_coverage Compliance framework satisfaction rate")
		fmt.Fprintln(w, "# TYPE stave_framework_coverage gauge")
		for i := range r.FrameworkTrends {
			ft := &r.FrameworkTrends[i]
			if len(ft.Scores) > 0 {
				latestScore := ft.Scores[len(ft.Scores)-1]
				fmt.Fprintf(w, "stave_framework_coverage{framework=%q} %g %d\n", ft.Framework, latestScore, tsMs)
			}
		}
		fmt.Fprintln(w)
	}

	// velocity_per_run
	fmt.Fprintln(w, "# HELP stave_velocity_per_run Net violation change per run")
	fmt.Fprintln(w, "# TYPE stave_velocity_per_run gauge")
	fmt.Fprintf(w, "stave_velocity_per_run %g %d\n\n", r.Velocity.AvgNetChange, tsMs)

	// posture_score (from severity component; partial without SLA/coverage config)
	if r.PostureScore > 0 {
		fmt.Fprintln(w, "# HELP stave_posture_score Security posture score (0-100)")
		fmt.Fprintln(w, "# TYPE stave_posture_score gauge")
		fmt.Fprintf(w, "stave_posture_score %.1f %d\n\n", r.PostureScore, tsMs)
	}

	fmt.Fprintln(w, "# EOF")
	return nil
}
