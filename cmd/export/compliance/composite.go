package compliance

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/version"
)

// CompositeEvidenceExport is the top-level output for multi-framework evaluation.
type CompositeEvidenceExport struct {
	ExportedAt   time.Time                   `json:"exported_at"`
	StaveVersion string                      `json:"stave_version"`
	Frameworks   []string                    `json:"frameworks"`
	PerFramework []FrameworkResultExport     `json:"per_framework"`
	Composite    evidence.CompositeGapReport `json:"composite_gaps"`
}

// FrameworkResultExport is a per-framework score summary.
type FrameworkResultExport struct {
	Framework string      `json:"framework"`
	Score     ScoreExport `json:"score"`
}

func runComposite(
	w io.Writer,
	opts *options,
	profiles []*evidence.FrameworkProfile,
	assessments []*evidence.ProfileAssessment,
	pkg *evidence.EvidencePackage,
	_ time.Time,
) error {
	// Build composite gap report.
	gapReport := evidence.BuildCompositeGaps(assessments)
	_ = pkg // reserved for future evidence-enrichment hookups; see BuildCompositeGaps doc.

	// Build export DTO.
	var frameworks []string
	var perFramework []FrameworkResultExport
	for i, profile := range profiles {
		a := assessments[i]
		frameworks = append(frameworks, profile.ID)
		perFramework = append(perFramework, FrameworkResultExport{
			Framework: profile.ID,
			Score: ScoreExport{
				RequirementsTotal:   a.TotalRequirements,
				RequirementsMet:     a.MetCount,
				RequirementsNotMet:  a.NotMetCount,
				RequirementsNotEval: a.NotEvaluatedCount,
				RequirementsIncomp:  a.IncompleteCount,
				OverallPercent:      a.CoveragePercent,
			},
		})
	}

	export := CompositeEvidenceExport{
		ExportedAt:   time.Now().UTC(),
		StaveVersion: version.String,
		Frameworks:   frameworks,
		PerFramework: perFramework,
		Composite:    gapReport,
	}

	renderer, err := NewRenderer(opts.Format, opts.Verbose)
	if err != nil {
		return err
	}
	if renderErr := renderer.Render(w, export); renderErr != nil {
		return renderErr
	}

	return exitErrorComposite(assessments)
}

func renderCompositeTable(w io.Writer, export CompositeEvidenceExport) {
	fmt.Fprintln(w, "COMPOSITE COMPLIANCE REPORT")
	fmt.Fprintf(w, "Frameworks: %s\n", strings.Join(export.Frameworks, " | "))
	fmt.Fprintln(w, strings.Repeat("=", 70))

	fmt.Fprintln(w, "\nPER-FRAMEWORK POSTURE")
	fmt.Fprintln(w, strings.Repeat("-", 70))
	for _, fr := range export.PerFramework {
		fmt.Fprintf(w, "  %-20s %3.0f%% satisfied  (%d/%d)\n",
			fr.Framework, fr.Score.OverallPercent,
			fr.Score.RequirementsMet, fr.Score.RequirementsTotal)
	}

	if len(export.Composite.SharedGaps) > 0 {
		fmt.Fprintln(w, "\nSHARED GAPS — Fix these first (highest cross-framework ROI)")
		fmt.Fprintln(w, strings.Repeat("-", 70))
		limit := min(len(export.Composite.SharedGaps), 10)
		for i := range limit {
			g := &export.Composite.SharedGaps[i]
			fwNames := make([]string, len(g.ViolatedFrameworks))
			for j, v := range g.ViolatedFrameworks {
				fwNames[j] = v.Framework
			}
			fmt.Fprintf(w, "  %d. %s  [%s]  closes %d obligations  (%s)\n",
				i+1, g.ControlID, strings.ToUpper(g.Severity),
				g.ObligationsClosed, strings.Join(fwNames, ", "))
			if g.ResourceARN != "" {
				fmt.Fprintf(w, "     %s\n", g.ResourceARN)
			}
			if g.RemediationAction != "" {
				action := g.RemediationAction
				if len(action) > 70 {
					action = action[:67] + "..."
				}
				fmt.Fprintf(w, "     Fix: %s\n", action)
			}
			for _, v := range g.ViolatedFrameworks {
				fmt.Fprintf(w, "     Satisfies: %s %s\n", v.Framework, v.RequirementID)
			}
		}
	}

	if len(export.Composite.TopNSharedGapImpact) > 0 {
		fmt.Fprintln(w, "\nTOP-N IMPACT ANALYSIS")
		fmt.Fprintln(w, strings.Repeat("-", 70))
		for _, t := range export.Composite.TopNSharedGapImpact {
			if t.TopNGaps == 0 {
				continue
			}
			fmt.Fprintf(w, "  Fix top %2d shared gaps -> closes %d/%d obligations (%.1f%%)\n",
				t.TopNGaps, t.ObligationsClosed, t.TotalObligations, t.ClosurePercent)
		}
	}

	if len(export.Composite.UniqueGaps) > 0 {
		fmt.Fprintf(w, "\nUNIQUE GAPS — Framework-specific (%d)\n", len(export.Composite.UniqueGaps))
		fmt.Fprintln(w, strings.Repeat("-", 70))
		byFW := make(map[string][]evidence.UniqueGap)
		for _, g := range export.Composite.UniqueGaps {
			byFW[g.Framework] = append(byFW[g.Framework], g)
		}
		for fw, gaps := range byFW {
			fmt.Fprintf(w, "  %s (%d gaps):\n", fw, len(gaps))
			for _, g := range gaps {
				fmt.Fprintf(w, "    %s  %s  %s\n", g.ControlID, g.ResourceARN, g.RequirementID)
			}
		}
	}

	fmt.Fprintf(w, "\nUnique gaps: %d  Shared gaps: %d\n",
		export.Composite.UniqueGapCount, len(export.Composite.SharedGaps))
}
