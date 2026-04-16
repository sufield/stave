package compare

import (
	"fmt"
	"io"
	"strings"
)

// WriteTable writes the gap analysis in table format.
func WriteTable(w io.Writer, r *Result) {
	fmt.Fprintln(w, "STAVE COMPLIANCE GAP ANALYSIS")
	fmt.Fprintf(w, "Baseline: %-12s (%d controls, %d failing)\n", r.Baseline.Profile, r.Baseline.Total, r.Baseline.Failing)
	fmt.Fprintf(w, "Target:   %-12s (%d controls, %d failing)\n\n", r.Target.Profile, r.Target.Total, r.Target.Failing)

	fmt.Fprintln(w, "ADOPTION READINESS")
	fmt.Fprintf(w, "  Readiness:             %.1f%%\n", r.AdoptionReadiness.ReadinessPct)
	fmt.Fprintf(w, "  Marginal findings:     %d (target-only)\n", r.AdoptionReadiness.MarginalFindings)
	fmt.Fprintf(w, "  Shared violations:     %d (fix once, satisfies both)\n", r.AdoptionReadiness.SharedViolations)
	fmt.Fprintln(w)

	if len(r.SharedViolations) > 0 {
		sep := strings.Repeat("-", 60)
		fmt.Fprintln(w, sep)
		fmt.Fprintln(w, "HIGHEST ROI — Fix these first (satisfy both frameworks)")
		fmt.Fprintln(w, sep)
		for _, item := range r.SharedViolations {
			fmt.Fprintf(w, "  %-30s %-8s  %s + %s\n",
				item.ControlID, strings.ToUpper(item.Severity), r.Baseline.Profile, r.Target.Profile)
		}
		fmt.Fprintln(w)
	}

	if len(r.TargetOnly) > 0 {
		sep := strings.Repeat("-", 60)
		fmt.Fprintln(w, sep)
		fmt.Fprintf(w, "MARGINAL WORK — Required only for %s\n", r.Target.Profile)
		fmt.Fprintln(w, sep)
		for _, item := range r.TargetOnly {
			cites := strings.Join(item.Target, ", ")
			fmt.Fprintf(w, "  %-30s %-8s  %s\n", item.ControlID, strings.ToUpper(item.Severity), cites)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "UPGRADE ROADMAP")
	fmt.Fprintf(w, "  Phase 1: %s (%d findings)\n", r.Roadmap.Phase1.Description, r.Roadmap.Phase1.Count)
	fmt.Fprintf(w, "  Phase 2: %s (%d findings)\n\n", r.Roadmap.Phase2.Description, r.Roadmap.Phase2.Count)

	fmt.Fprintln(w, "SUMMARY FOR LEADERSHIP")
	fmt.Fprintln(w, r.LeadershipSummary)
}

// WriteMarkdown writes the gap analysis as markdown.
func WriteMarkdown(w io.Writer, r *Result) {
	fmt.Fprintf(w, "# Compliance Gap Analysis: %s → %s\n\n", r.Baseline.Profile, r.Target.Profile)
	fmt.Fprintf(w, "**Generated:** %s\n\n", r.GeneratedAt)
	fmt.Fprintf(w, "## Adoption Readiness: %.1f%%\n\n", r.AdoptionReadiness.ReadinessPct)
	fmt.Fprintln(w, r.LeadershipSummary)
	fmt.Fprintln(w)

	if len(r.SharedViolations) > 0 {
		fmt.Fprintln(w, "## Highest ROI Findings (Fix Once, Satisfy Both)")
		fmt.Fprintln(w)
		fmt.Fprintf(w, "| Control | Severity | %s | %s |\n", r.Baseline.Profile, r.Target.Profile)
		fmt.Fprintln(w, "|---------|----------|------|------|")
		for _, item := range r.SharedViolations {
			fmt.Fprintf(w, "| %s | %s | %s | %s |\n",
				item.ControlID, strings.ToUpper(item.Severity),
				strings.Join(item.Baseline, ", "), strings.Join(item.Target, ", "))
		}
		fmt.Fprintln(w)
	}

	if len(r.TargetOnly) > 0 {
		fmt.Fprintf(w, "## %s-Specific Gaps (%d findings)\n\n", r.Target.Profile, len(r.TargetOnly))
		fmt.Fprintf(w, "| Control | Severity | %s Requirement |\n", r.Target.Profile)
		fmt.Fprintln(w, "|---------|----------|----------------|")
		for _, item := range r.TargetOnly {
			fmt.Fprintf(w, "| %s | %s | %s |\n",
				item.ControlID, strings.ToUpper(item.Severity), strings.Join(item.Target, ", "))
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "## Upgrade Roadmap")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Phase 1** (%d findings): %s\n\n", r.Roadmap.Phase1.Count, r.Roadmap.Phase1.Description)
	fmt.Fprintf(w, "**Phase 2** (%d findings): %s\n", r.Roadmap.Phase2.Count, r.Roadmap.Phase2.Description)
}
