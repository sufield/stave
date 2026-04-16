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

	// SLA compliance rate (only when SLA data exists)
	if len(r.SLATrend) > 0 {
		latestSLA := &r.SLATrend[len(r.SLATrend)-1]
		slaTs := latestSLA.CapturedAt.UnixMilli()

		fmt.Fprintln(w, "# HELP stave_sla_compliance_rate Fraction of findings remediated within SLA (0-1)")
		fmt.Fprintln(w, "# TYPE stave_sla_compliance_rate gauge")
		fmt.Fprintf(w, "stave_sla_compliance_rate %g %d\n\n", latestSLA.CompliancePercent/100, slaTs)

		fmt.Fprintln(w, "# HELP stave_sla_breached_total Current count of SLA-breached findings")
		fmt.Fprintln(w, "# TYPE stave_sla_breached_total gauge")
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			count := latestSLA.BreachedBySev[sev]
			fmt.Fprintf(w, "stave_sla_breached_total{severity=%q} %d %d\n", sev, count, slaTs)
		}
		fmt.Fprintln(w)
	}

	// Posture score (when available).
	if r.PostureScore != nil {
		fmt.Fprintln(w, "# HELP stave_posture_score Security posture score (0-100)")
		fmt.Fprintln(w, "# TYPE stave_posture_score gauge")
		fmt.Fprintf(w, "stave_posture_score %.1f %d\n\n", *r.PostureScore, tsMs)
	}

	// Per-team metrics.
	if len(r.TeamTrends) > 0 {
		fmt.Fprintln(w, "# HELP stave_team_posture_score Current posture score per team")
		fmt.Fprintln(w, "# TYPE stave_team_posture_score gauge")
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			fmt.Fprintf(w, "stave_team_posture_score{team=%q} %.1f %d\n", t.ID, t.PostureScore, tsMs)
		}
		fmt.Fprintln(w)

		fmt.Fprintln(w, "# HELP stave_team_posture_delta Posture score change over window")
		fmt.Fprintln(w, "# TYPE stave_team_posture_delta gauge")
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			fmt.Fprintf(w, "stave_team_posture_delta{team=%q} %.1f %d\n", t.ID, t.ScoreDelta, tsMs)
		}
		fmt.Fprintln(w)

		fmt.Fprintln(w, "# HELP stave_team_mttr_hours Mean time to remediate per team")
		fmt.Fprintln(w, "# TYPE stave_team_mttr_hours gauge")
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			fmt.Fprintf(w, "stave_team_mttr_hours{team=%q} %.1f %d\n", t.ID, t.MTTRHours, tsMs)
		}
		fmt.Fprintln(w)

		fmt.Fprintln(w, "# HELP stave_team_sla_compliance_pct SLA compliance percentage per team")
		fmt.Fprintln(w, "# TYPE stave_team_sla_compliance_pct gauge")
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			fmt.Fprintf(w, "stave_team_sla_compliance_pct{team=%q} %.1f %d\n", t.ID, t.SLACompPct, tsMs)
		}
		fmt.Fprintln(w)

		fmt.Fprintln(w, "# HELP stave_team_trajectory Team posture trajectory (-1=regressing,0=stable,1=improving)")
		fmt.Fprintln(w, "# TYPE stave_team_trajectory gauge")
		for i := range r.TeamTrends {
			t := &r.TeamTrends[i]
			val := 0
			switch t.Trajectory {
			case trajectoryImproving:
				val = 1
			case trajectoryRegressing:
				val = -1
			}
			fmt.Fprintf(w, "stave_team_trajectory{team=%q} %d %d\n", t.ID, val, tsMs)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "# EOF")
	return nil
}
