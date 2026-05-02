package score

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	appscore "github.com/sufield/stave/internal/app/score"
)

func renderResult(w io.Writer, r appscore.Result, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "openmetrics":
		writeOpenMetrics(w, r)
		return nil
	default:
		writeTable(w, r)
		return nil
	}
}

func writeTable(w io.Writer, r appscore.Result) {
	fmt.Fprintln(w, "SECURITY POSTURE SCORE")

	if r.SnapshotID != "" {
		fmt.Fprintf(w, "Assessment: %s  |  Evaluated: %s\n",
			r.SnapshotID, r.GeneratedAt.Format("2006-01-02 15:04 UTC"))
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "SCORE:  %.1f / 100   %s\n", r.Score, strings.ToUpper(r.RubricBand))
	fmt.Fprintln(w, strings.Repeat("\u2500", 64))

	fmt.Fprintln(w, "\nSCORE DECOMPOSITION")
	fmt.Fprintf(w, "  Severity score:   %.2f \u00d7 %.2f = %5.1f pts  (of %.0f max)\n",
		r.Severity.SubScore, r.Severity.Weight, r.Severity.Contribution, r.Severity.MaxContribution)
	fmt.Fprintf(w, "  SLA score:        %.2f \u00d7 %.2f = %5.1f pts  (of %.0f max)\n",
		r.SLA.SubScore, r.SLA.Weight, r.SLA.Contribution, r.SLA.MaxContribution)
	fmt.Fprintf(w, "  Chain score:      %.2f \u00d7 %.2f = %5.1f pts  (of %.0f max)\n",
		r.Chain.SubScore, r.Chain.Weight, r.Chain.Contribution, r.Chain.MaxContribution)
	fmt.Fprintf(w, "  Coverage score:   %.2f \u00d7 %.2f = %5.1f pts  (of %.0f max)\n",
		r.Coverage.SubScore, r.Coverage.Weight, r.Coverage.Contribution, r.Coverage.MaxContribution)

	// WHAT MOVED THE SCORE section.
	movers := scoreMovers(r)
	if len(movers) > 0 {
		fmt.Fprintln(w, "\nWHAT MOVED THE SCORE")
		for _, m := range movers {
			fmt.Fprintf(w, "  %s\n", m)
		}
	}

	fmt.Fprintf(w, "\nRUBRIC:  %.1f = %s\n", r.Score, strings.ToUpper(r.RubricBand))
	fmt.Fprintf(w, "  %s\n", r.RubricDesc)

	// Trend section.
	if len(r.Trend) > 0 {
		fmt.Fprintln(w, "\nTREND (last runs):")
		for _, tp := range r.Trend {
			bar := scoreBar(tp.Score)
			fmt.Fprintf(w, "  %s  %5.1f  %s\n",
				tp.Timestamp.Format("2006-01-02"), tp.Score, bar)
		}
		first := r.Trend[0].Score
		last := r.Trend[len(r.Trend)-1].Score
		netChange := last - first
		direction := "STABLE"
		if netChange > 1 {
			direction = "IMPROVING"
		} else if netChange < -1 {
			direction = "DECLINING"
		}
		fmt.Fprintf(w, "\nNet change: %+.1f pts  Direction: %s\n", netChange, direction)
	}
}

func scoreMovers(r appscore.Result) []string {
	moversData := r.Movers()
	if len(moversData) == 0 {
		return nil
	}
	out := make([]string, 0, len(moversData))
	for _, m := range moversData {
		out = append(out, formatMover(m))
	}
	return out
}

// formatMover decorates the structured ScoreMover with the arrow
// prefix and points-lost suffix used by the CLI render. The
// component-to-message mapping lives on ScoreMover.Label so
// adding a new mover component is one edit on the type.
func formatMover(m appscore.ScoreMover) string {
	return fmt.Sprintf("\u2193 %-40s (\u2212%.1f pts)", m.Label(), m.PointsLost)
}

func scoreBar(score float64) string {
	// Clamp to [0, 20]: a score above 100 (which compute() now never
	// produces, but a future caller passing a raw weighted total
	// could) would otherwise drive strings.Repeat past 20 cells and
	// blow the bar's width. A negative score becomes an all-empty bar.
	filled := max(0, min(int(math.Round(score/5)), 20))
	empty := 20 - filled
	return strings.Repeat("\u2588", filled) + strings.Repeat("\u2591", empty)
}

func writeOpenMetrics(w io.Writer, r appscore.Result) {
	tsMs := r.GeneratedAt.UnixMilli()

	fmt.Fprintln(w, "# HELP stave_posture_score Security posture score (0-100)")
	fmt.Fprintln(w, "# TYPE stave_posture_score gauge")
	fmt.Fprintf(w, "stave_posture_score %.1f %d\n", r.Score, tsMs)

	fmt.Fprintln(w, "# HELP stave_posture_score_severity_component Severity sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_severity_component gauge")
	fmt.Fprintf(w, "stave_posture_score_severity_component %.2f %d\n", r.Severity.SubScore, tsMs)

	fmt.Fprintln(w, "# HELP stave_posture_score_sla_component SLA compliance sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_sla_component gauge")
	fmt.Fprintf(w, "stave_posture_score_sla_component %.2f %d\n", r.SLA.SubScore, tsMs)

	fmt.Fprintln(w, "# HELP stave_posture_score_chain_component Chain activity sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_chain_component gauge")
	fmt.Fprintf(w, "stave_posture_score_chain_component %.2f %d\n", r.Chain.SubScore, tsMs)

	fmt.Fprintln(w, "# HELP stave_posture_score_coverage_component Framework coverage sub-score (0-1)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_coverage_component gauge")
	fmt.Fprintf(w, "stave_posture_score_coverage_component %.2f %d\n", r.Coverage.SubScore, tsMs)

	// Rubric band as numeric gauge.
	fmt.Fprintln(w, "# HELP stave_posture_score_rubric_band Rubric band (0=critical,1=at_risk,2=needs_attention,3=adequate,4=strong)")
	fmt.Fprintln(w, "# TYPE stave_posture_score_rubric_band gauge")
	fmt.Fprintf(w, "stave_posture_score_rubric_band %d %d\n", r.RubricBandNumeric(), tsMs)

	fmt.Fprintln(w, "# EOF")
}
