package trendcmd

import (
	"fmt"
	"io"
)

func renderTrendOpenMetrics(out io.Writer, r *trendReport) error {
	w := &trendErrWriter{w: out}
	if !r.HasRuns() {
		fmt.Fprintln(w, "# EOF")
		return w.err
	}

	latest := &r.Runs[len(r.Runs)-1]
	tsMs := latest.CapturedAt.UnixMilli()

	emitViolationMetrics(w, latest, tsMs)
	emitMTTRMetrics(w, r.MTTR, tsMs)
	emitFrameworkMetrics(w, r.FrameworkTrends, tsMs)

	fmt.Fprintln(w, "# HELP stave_velocity_per_run Net violation change per run")
	fmt.Fprintln(w, "# TYPE stave_velocity_per_run gauge")
	fmt.Fprintf(w, "stave_velocity_per_run %g %d\n\n", r.Velocity.AvgNetChange, tsMs)

	// SLA compliance rate (only when SLA data exists)
	if r.HasSLATrend() {
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

	if r.HasTeamTrends() {
		renderTeamOpenMetrics(w, r.TeamTrends, tsMs)
	}

	fmt.Fprintln(w, "# EOF")
	return w.err
}

func emitViolationMetrics(w io.Writer, latest *runMetrics, tsMs int64) {
	fmt.Fprintln(w, "# HELP stave_violations_total Current violation count by severity")
	fmt.Fprintln(w, "# TYPE stave_violations_total gauge")
	for sev, count := range latest.BySeverity {
		fmt.Fprintf(w, "stave_violations_total{severity=%q} %d %d\n", sev, count, tsMs)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP stave_violation_rate Current violation rate")
	fmt.Fprintln(w, "# TYPE stave_violation_rate gauge")
	fmt.Fprintf(w, "stave_violation_rate %g %d\n\n", latest.ViolationRate, tsMs)
}

func emitMTTRMetrics(w io.Writer, mttr map[string]mttrEntry, tsMs int64) {
	if len(mttr) == 0 {
		return
	}
	fmt.Fprintln(w, "# HELP stave_mttr_days Mean time to remediate by severity")
	fmt.Fprintln(w, "# TYPE stave_mttr_days gauge")
	for sev, entry := range mttr {
		fmt.Fprintf(w, "stave_mttr_days{severity=%q} %g %d\n", sev, entry.AvgDays, tsMs)
	}
	fmt.Fprintln(w)
}

func emitFrameworkMetrics(w io.Writer, trends []frameworkTrend, tsMs int64) {
	if len(trends) == 0 {
		return
	}
	fmt.Fprintln(w, "# HELP stave_framework_coverage Compliance framework satisfaction rate")
	fmt.Fprintln(w, "# TYPE stave_framework_coverage gauge")
	for i := range trends {
		ft := &trends[i]
		if len(ft.Scores) > 0 {
			latestScore := ft.Scores[len(ft.Scores)-1]
			fmt.Fprintf(w, "stave_framework_coverage{framework=%q} %g %d\n", ft.Framework, latestScore, tsMs)
		}
	}
	fmt.Fprintln(w)
}

func renderTeamOpenMetrics(w io.Writer, trends []teamTrend, tsMs int64) {
	fmt.Fprintln(w, "# HELP stave_team_posture_score Current posture score per team")
	fmt.Fprintln(w, "# TYPE stave_team_posture_score gauge")
	for i := range trends {
		t := &trends[i]
		fmt.Fprintf(w, "stave_team_posture_score{team=%q} %.1f %d\n", t.ID, t.PostureScore, tsMs)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP stave_team_posture_delta Posture score change over window")
	fmt.Fprintln(w, "# TYPE stave_team_posture_delta gauge")
	for i := range trends {
		t := &trends[i]
		fmt.Fprintf(w, "stave_team_posture_delta{team=%q} %.1f %d\n", t.ID, t.ScoreDelta, tsMs)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP stave_team_mttr_hours Mean time to remediate per team")
	fmt.Fprintln(w, "# TYPE stave_team_mttr_hours gauge")
	for i := range trends {
		t := &trends[i]
		fmt.Fprintf(w, "stave_team_mttr_hours{team=%q} %.1f %d\n", t.ID, t.MTTRHours, tsMs)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP stave_team_sla_compliance_pct SLA compliance percentage per team")
	fmt.Fprintln(w, "# TYPE stave_team_sla_compliance_pct gauge")
	for i := range trends {
		t := &trends[i]
		fmt.Fprintf(w, "stave_team_sla_compliance_pct{team=%q} %.1f %d\n", t.ID, t.SLACompPct, tsMs)
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "# HELP stave_team_trajectory Team posture trajectory (-1=regressing,0=stable,1=improving)")
	fmt.Fprintln(w, "# TYPE stave_team_trajectory gauge")
	for i := range trends {
		t := &trends[i]
		fmt.Fprintf(w, "stave_team_trajectory{team=%q} %d %d\n", t.ID, t.MetricValue(), tsMs)
	}
	fmt.Fprintln(w)
}
