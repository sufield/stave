// Package coverage provides ATT&CK tactic coverage analysis.
package coverage

import (
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/attack"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// AllTactics is the complete ATT&CK enterprise tactic list.
var AllTactics = []TacticDef{
	{ID: "TA0001", Name: "Initial Access", StaveID: kernel.AttackStageInitialAccess},
	{ID: "TA0002", Name: "Execution", StaveID: kernel.AttackStageExecution},
	{ID: "TA0003", Name: "Persistence", StaveID: kernel.AttackStagePersistence},
	{ID: "TA0004", Name: "Privilege Escalation", StaveID: kernel.AttackStagePrivilegeEscalation},
	{ID: "TA0005", Name: "Defense Evasion", StaveID: kernel.AttackStageDetectionEvasion},
	{ID: "TA0006", Name: "Credential Access", StaveID: kernel.AttackStageCredentialAccess},
	{ID: "TA0007", Name: "Discovery", StaveID: kernel.AttackStageDiscovery},
	{ID: "TA0008", Name: "Lateral Movement", StaveID: kernel.AttackStageLateralMovement},
	{ID: "TA0009", Name: "Collection", StaveID: kernel.AttackStageCollection},
	{ID: "TA0010", Name: "Exfiltration", StaveID: kernel.AttackStageExfiltration},
	{ID: "TA0040", Name: "Impact", StaveID: kernel.AttackStageImpact},
}

// TacticDef maps ATT&CK tactic ID to name and Stave AttackStage.
type TacticDef struct {
	ID      string
	Name    string
	StaveID kernel.AttackStage
}

// TacticStatus classifies the coverage level of a tactic.
type TacticStatus string

// Tactic-coverage status vocabulary. Centralised here so producers
// (the Build pipeline) and consumers (execreport, exporters) cannot
// drift on the literal strings — a future rename or addition is one
// edit. Values are the on-the-wire JSON strings.
const (
	StatusCovered    TacticStatus = "covered"
	StatusThin       TacticStatus = "thin"
	StatusNoCoverage TacticStatus = "no_coverage"
)

// TacticCoverage holds coverage data for a single tactic.
type TacticCoverage struct {
	TacticID        string             `json:"tactic_id"`
	TacticName      string             `json:"tactic_name"`
	ControlCount    int                `json:"control_count"`
	Controls        []kernel.ControlID `json:"controls"`
	PassingCount    *int               `json:"passing_count"`    // nil when no assessment overlay
	FailingCount    *int               `json:"failing_count"`    // nil when no assessment overlay
	CoveragePercent *float64           `json:"coverage_percent"` // nil when no controls
	Status          TacticStatus       `json:"status"`           // covered | thin | no_coverage
}

// IsCovered reports whether this tactic has at least the "thin"
// level of control coverage — the gate the execreport summary uses
// to count tactics towards the coverage percentage. Replaces the
// (Status == "covered" || Status == "thin") OR-pair at
// internal/app/execreport/builder_helpers.go:199 so the producer
// owns the threshold definition.
func (tc *TacticCoverage) IsCovered() bool {
	return tc != nil && (tc.Status == StatusCovered || tc.Status == StatusThin)
}

// DisplayStatus returns the tactic's status in uppercase for the
// `stave map` report column. Centralised so cmd-side renderers
// stop calling strings.ToUpper inline at every site.
func (tc *TacticCoverage) DisplayStatus() string {
	if tc == nil {
		return ""
	}
	return strings.ToUpper(string(tc.Status))
}

// IsGap reports whether this tactic is a coverage gap — either no
// controls map to it or the count is below the "thin" threshold.
// Complements IsCovered (the inverse) and replaces the
// (Status == "no_coverage" || Status == "thin") OR-pair at
// cmd/map/cmd.go:128. Note that "thin" coverage is both IsCovered
// and IsGap by design: the gate counts it as covered for the
// summary, but the map renderer flags it as still-needing-work.
func (tc *TacticCoverage) IsGap() bool {
	return tc != nil && (tc.Status == StatusNoCoverage || tc.Status == StatusThin)
}

// StatusLabel returns the user-facing label for this tactic's
// status. The wire-level "no_coverage" is normalised to
// "not_covered" for the execreport rendering to match operator
// expectations; everything else passes through unchanged.
// Replaces the inline normalisation in
// internal/app/execreport/builder_helpers.go:194-197.
func (tc *TacticCoverage) StatusLabel() string {
	if tc == nil {
		return ""
	}
	if tc.Status == StatusNoCoverage {
		return "not_covered"
	}
	return string(tc.Status)
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
	byStage := make(map[kernel.AttackStage][]kernel.ControlID) // stave_stage → []controlID
	var unannotated []string
	for i := range input.Controls {
		ctl := &input.Controls[i]
		stage := ctl.AttackStage()
		if stage == "" {
			unannotated = append(unannotated, string(ctl.ID))
			continue
		}
		byStage[stage] = append(byStage[stage], ctl.ID)
	}

	// Group findings by control ID for posture overlay.
	var failingControls map[kernel.ControlID]struct{}
	hasOverlay := len(input.Findings) > 0
	if hasOverlay {
		failingControls = make(map[kernel.ControlID]struct{})
		for i := range input.Findings {
			failingControls[input.Findings[i].ControlID] = struct{}{}
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
			tc.Status = StatusNoCoverage
			noCoverageCount++
		} else if len(ctls) < input.MinControls {
			tc.Status = StatusThin
			thinCount++
			coveredCount++
		} else {
			tc.Status = StatusCovered
			coveredCount++
		}

		if hasOverlay && len(ctls) > 0 {
			passing := 0
			failing := 0
			for _, cid := range ctls {
				if _, ok := failingControls[cid]; ok {
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
	if ctls := byStage[kernel.AttackStageResilience]; len(ctls) > 0 {
		so := StaveOnlyTactic{
			TacticID:     "x_stave_resilience",
			TacticName:   "Resilience",
			ControlCount: len(ctls),
		}
		if hasOverlay {
			passing := 0
			failing := 0
			for _, cid := range ctls {
				if _, ok := failingControls[cid]; ok {
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
	if report == nil {
		return nil
	}
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
			return attack.ToATTCKTacticID(td.StaveID) // returns same ID but validates
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
