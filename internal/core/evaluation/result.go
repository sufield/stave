package evaluation

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// ConfidenceLevel quantifies the certainty of an evaluation result.
type ConfidenceLevel string

const (
	ConfidenceHigh         ConfidenceLevel = "high"
	ConfidenceMedium       ConfidenceLevel = "medium"
	ConfidenceLow          ConfidenceLevel = "low"
	ConfidenceInconclusive ConfidenceLevel = "inconclusive"
)

// SafetyStatus classifies the high-level security posture based on evaluation results.
type SafetyStatus string

const (
	StatusSafe       SafetyStatus = "SAFE"
	StatusBorderline SafetyStatus = "BORDERLINE"
	StatusUnsafe     SafetyStatus = "UNSAFE"
)

// ClassifySafetyStatus derives posture from violation counts and approaching risks.
func ClassifySafetyStatus(violations int, upcoming risk.ThresholdItems) SafetyStatus {
	if violations > 0 {
		return StatusUnsafe
	}
	if upcoming.HasAnyRisk() {
		return StatusBorderline
	}
	return StatusSafe
}

// Decision represents the final outcome of a control check against a resource.
type Decision string

const (
	DecisionViolation     Decision = "VIOLATION"
	DecisionPass          Decision = "PASS"
	DecisionInconclusive  Decision = "INCONCLUSIVE"
	DecisionNotApplicable Decision = "NOT_APPLICABLE"
	DecisionSkipped       Decision = "SKIPPED"
)

// Row captures the granular result for a single control/asset pairing.
type Row struct {
	ControlID   kernel.ControlID   `json:"control_id"`
	AssetID     asset.ID           `json:"asset_id"`
	AssetType   kernel.AssetType   `json:"asset_type"`
	AssetDomain kernel.AssetDomain `json:"asset_domain"`
	Decision    Decision           `json:"decision"`
	Confidence  ConfidenceLevel    `json:"confidence"`
	Evidence    *Evidence          `json:"evidence,omitempty"`
	WhyNow      string             `json:"why_now,omitempty"`
	Reason      string             `json:"reason,omitempty"` // populated for SKIPPED/INCONCLUSIVE
}

// MarkInconclusive shifts a row to an inconclusive state with a specific explanation.
func (r *Row) MarkInconclusive(reason string) {
	if r == nil {
		return
	}
	r.Decision = DecisionInconclusive
	r.Confidence = ConfidenceInconclusive
	r.Reason = reason
}

// Summary provides high-level metrics for an evaluation run.
type Summary struct {
	AssetsEvaluated int `json:"assets_evaluated"`
	AttackSurface   int `json:"attack_surface"`
	Violations      int `json:"violations"`
}

// SkippedControl identifies a control that was ignored during the run.
type SkippedControl struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// Result is the root aggregate of an evaluation execution.
type Result struct {
	Run              RunInfo               `json:"run"`
	Summary          Summary               `json:"summary"`
	SafetyStatus     SafetyStatus          `json:"safety_status"`
	AtRisk           risk.ThresholdItems   `json:"at_risk,omitempty"`
	Findings         []Finding             `json:"findings"`
	ExceptedFindings []ExceptedFinding     `json:"excepted_findings,omitempty"`
	Skipped          []SkippedControl      `json:"skipped,omitempty"`
	ExemptedAssets   []asset.ExemptedAsset `json:"exempted_assets,omitempty"`
	Metadata         Metadata              `json:"-"`
	Rows             []Row                 `json:"rows,omitempty"` // populated if --explain is used
}

// FindFinding retrieves a finding for a specific control/asset pair, returning nil if not found.
func (r *Result) FindFinding(ctlID kernel.ControlID, astID asset.ID) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ControlID == ctlID && r.Findings[i].AssetID == astID {
			return &r.Findings[i]
		}
	}
	return nil
}
