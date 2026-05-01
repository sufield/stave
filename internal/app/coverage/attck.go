// Package coverage provides ATT&CK tactic coverage analysis.
package coverage

import (
	"fmt"
	"slices"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/graph"
)

// AllTactics is the complete ATT&CK enterprise tactic list.
var AllTactics = []TacticDef{
	{ID: "TA0001", Name: "Initial Access", StaveID: "initial_access"},
	{ID: "TA0002", Name: "Execution", StaveID: "execution"},
	{ID: "TA0003", Name: "Persistence", StaveID: "persistence"},
	{ID: "TA0004", Name: "Privilege Escalation", StaveID: "privilege_escalation"},
	{ID: "TA0005", Name: "Defense Evasion", StaveID: "detection_evasion"},
	{ID: "TA0006", Name: "Credential Access", StaveID: "credential_access"},
	{ID: "TA0007", Name: "Discovery", StaveID: "discovery"},
	{ID: "TA0008", Name: "Lateral Movement", StaveID: "lateral_movement"},
	{ID: "TA0009", Name: "Collection", StaveID: "collection"},
	{ID: "TA0010", Name: "Exfiltration", StaveID: "exfiltration"},
	{ID: "TA0040", Name: "Impact", StaveID: "impact"},
}

// TacticDef maps ATT&CK tactic ID to name and Stave string.
type TacticDef struct {
	ID      string
	Name    string
	StaveID string
}

// TacticCoverage holds coverage data for a single tactic.
type TacticCoverage struct {
	TacticID        string   `json:"tactic_id"`
	TacticName      string   `json:"tactic_name"`
	ControlCount    int      `json:"control_count"`
	Controls        []string `json:"controls"`
	PassingCount    *int     `json:"passing_count"`    // nil when no assessment overlay
	FailingCount    *int     `json:"failing_count"`    // nil when no assessment overlay
	CoveragePercent *float64 `json:"coverage_percent"` // nil when no controls
	Status          string   `json:"status"`           // covered | thin | no_coverage
}

// StaveOnlyTactic is for Stave-specific tactics not in ATT&CK.
type StaveOnlyTactic struct {
	TacticID     string `json:"tactic_id"`
	TacticName   string `json:"tactic_name"`
	ControlCount int    `json:"control_count"`
	PassingCount *int   `json:"passing_count"`
	FailingCount *int   `json:"failing_count"`
}

// CoverageReport is the full coverage analysis output.
type CoverageReport struct {
	Framework           string            `json:"framework"`
	ControlsAnalyzed    int               `json:"controls_analyzed"`
	ControlsAnnotated   int               `json:"controls_annotated"`
	ControlsUnannotated int               `json:"controls_unannotated"`
	AssessmentOverlay   bool              `json:"assessment_overlay"`
	Tactics             []TacticCoverage  `json:"tactics"`
	StaveOnly           []StaveOnlyTactic `json:"stave_only,omitempty"`
	UnannotatedControls []string          `json:"unannotated_controls,omitempty"`
	Summary             CoverageSummary   `json:"summary"`
}

// CoverageSummary holds aggregate metrics.
type CoverageSummary struct {
	TacticsCovered          int     `json:"tactics_covered"`
	TacticsTotal            int     `json:"tactics_total"`
	TacticsThin             int     `json:"tactics_thin"`
	TacticsNoCoverage       int     `json:"tactics_no_coverage"`
	WeightedCoveragePercent float64 `json:"weighted_coverage_percent"`
}

// BuildInput holds data for coverage analysis.
type BuildInput struct {
	Controls    []policy.ControlDefinition
	Findings    []remediation.Finding // nil for static coverage only
	MinControls int                   // threshold for "thin" (default: 2)
}

// Build produces a coverage report from controls and optional findings.
func Build(input BuildInput) *CoverageReport {
	if input.MinControls <= 0 {
		input.MinControls = 2
	}

	// Group controls by attack stage.
	byStage := make(map[string][]string) // stave_stage → []controlID
	var unannotated []string
	for i := range input.Controls {
		ctl := &input.Controls[i]
		stage := ctl.AttackStage()
		if stage == "" {
			unannotated = append(unannotated, string(ctl.ID))
			continue
		}
		byStage[string(stage)] = append(byStage[string(stage)], string(ctl.ID))
	}

	// Group findings by control ID for posture overlay.
	var failingControls map[kernel.ControlID]bool
	hasOverlay := len(input.Findings) > 0
	if hasOverlay {
		failingControls = make(map[kernel.ControlID]bool)
		for i := range input.Findings {
			failingControls[input.Findings[i].ControlID] = true
		}
	}

	// Build per-tactic coverage.
	var tactics []TacticCoverage
	coveredCount := 0
	thinCount := 0
	noCoverageCount := 0
	totalPassing := 0
	totalControls := 0

	for _, td := range AllTactics {
		ctls := byStage[td.StaveID]
		tc := TacticCoverage{
			TacticID:     td.ID,
			TacticName:   td.Name,
			ControlCount: len(ctls),
			Controls:     ctls,
		}

		if len(ctls) == 0 {
			tc.Status = "no_coverage"
			noCoverageCount++
		} else if len(ctls) < input.MinControls {
			tc.Status = "thin"
			thinCount++
			coveredCount++
		} else {
			tc.Status = "covered"
			coveredCount++
		}

		if hasOverlay && len(ctls) > 0 {
			passing := 0
			failing := 0
			for _, cid := range ctls {
				if failingControls[kernel.ControlID(cid)] {
					failing++
				} else {
					passing++
				}
			}
			tc.PassingCount = &passing
			tc.FailingCount = &failing
			if len(ctls) > 0 {
				pct := float64(passing) / float64(len(ctls)) * 100
				tc.CoveragePercent = &pct
			}
			totalPassing += passing
			totalControls += len(ctls)
		}

		tactics = append(tactics, tc)
	}

	// Stave-only tactics (resilience).
	var staveOnly []StaveOnlyTactic
	if ctls := byStage["resilience"]; len(ctls) > 0 {
		so := StaveOnlyTactic{
			TacticID:     "x_stave_resilience",
			TacticName:   "Resilience",
			ControlCount: len(ctls),
		}
		if hasOverlay {
			passing := 0
			failing := 0
			for _, cid := range ctls {
				if failingControls[kernel.ControlID(cid)] {
					failing++
				} else {
					passing++
				}
			}
			so.PassingCount = &passing
			so.FailingCount = &failing
		}
		staveOnly = append(staveOnly, so)
	}

	// Weighted coverage.
	var weightedPct float64
	if totalControls > 0 {
		weightedPct = float64(totalPassing) / float64(totalControls) * 100
	}

	slices.Sort(unannotated)

	return &CoverageReport{
		Framework:           "mitre-attack",
		ControlsAnalyzed:    len(input.Controls),
		ControlsAnnotated:   len(input.Controls) - len(unannotated),
		ControlsUnannotated: len(unannotated),
		AssessmentOverlay:   hasOverlay,
		Tactics:             tactics,
		StaveOnly:           staveOnly,
		UnannotatedControls: unannotated,
		Summary: CoverageSummary{
			TacticsCovered:          coveredCount,
			TacticsTotal:            len(AllTactics),
			TacticsThin:             thinCount,
			TacticsNoCoverage:       noCoverageCount,
			WeightedCoveragePercent: weightedPct,
		},
	}
}

// NavigatorLayer produces an ATT&CK Navigator layer JSON.
func NavigatorLayer(report *CoverageReport) map[string]any {
	techniques := make([]map[string]any, 0, len(report.Tactics))
	for i := range report.Tactics {
		tc := &report.Tactics[i]
		tech := map[string]any{
			"techniqueID": tc.TacticID,
			"tactic":      staveToNavigatorTactic(tc.TacticID),
			"comment":     formatComment(tc),
		}
		if tc.CoveragePercent != nil {
			tech["score"] = int(*tc.CoveragePercent)
		} else if tc.ControlCount > 0 {
			tech["score"] = 50 // static coverage, no posture
		} else {
			tech["score"] = 0
			tech["color"] = "#ff6666"
		}
		techniques = append(techniques, tech)
	}

	return map[string]any{
		"name":        "Stave Coverage",
		"versions":    map[string]string{"attack": "14", "navigator": "4.9", "layer": "4.5"},
		"domain":      "enterprise-attack",
		"description": "Stave control catalog ATT&CK tactic coverage",
		"techniques":  techniques,
		"gradient": map[string]any{
			"colors":   []string{"#ff6666", "#ffe766", "#8ec843"},
			"minValue": 0,
			"maxValue": 100,
		},
	}
}

func staveToNavigatorTactic(tacticID string) string {
	for _, td := range AllTactics {
		if td.ID == tacticID {
			return graph.ToATTCKTacticID(kernel.AttackStage(td.StaveID)) // returns same ID but validates
		}
	}
	return ""
}

func formatComment(tc *TacticCoverage) string {
	if tc.ControlCount == 0 {
		return "NO COVERAGE — 0 controls"
	}
	if tc.PassingCount != nil {
		return fmt.Sprintf("%d controls — %d passing, %d failing", tc.ControlCount, *tc.PassingCount, *tc.FailingCount)
	}
	return fmt.Sprintf("%d controls", tc.ControlCount)
}
