package evaluation

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// ConfidenceLevel quantifies the certainty of an evaluation result.
type ConfidenceLevel string

// ConfidenceHigh and related constants.
const (
	ConfidenceHigh         ConfidenceLevel = "high"
	ConfidenceMedium       ConfidenceLevel = "medium"
	ConfidenceLow          ConfidenceLevel = "low"
	ConfidenceInconclusive ConfidenceLevel = "inconclusive"
)

// SecurityState classifies the high-level security posture of the environment.
type SecurityState string

// StateCompliant and related constants.
const (
	StateCompliant    SecurityState = "COMPLIANT"
	StateAtRisk       SecurityState = "AT_RISK"
	StateNonCompliant SecurityState = "NON_COMPLIANT"
)

// DeriveSecurityState determines the overall health based on violation counts and drift risks.
func DeriveSecurityState(violations int, upcoming risk.ThresholdItems) SecurityState {
	if violations > 0 {
		return StateNonCompliant
	}
	if upcoming.HasAnyRisk() {
		return StateAtRisk
	}
	return StateCompliant
}

// Verdict represents the final outcome of a control check against a resource.
type Verdict string

// VerdictViolation and related constants.
const (
	VerdictViolation     Verdict = "VIOLATION"
	VerdictPass          Verdict = "PASS"
	VerdictInconclusive  Verdict = "INCONCLUSIVE"
	VerdictNotApplicable Verdict = "NOT_APPLICABLE"
	VerdictSkipped       Verdict = "SKIPPED"
)

// ResourceCheck captures the granular result for a single control/asset pairing.
type ResourceCheck struct {
	ControlID    kernel.ControlID   `json:"control_id"`
	AssetID      asset.ID           `json:"asset_id"`
	AssetType    kernel.AssetType   `json:"asset_type"`
	AssetDomain  kernel.AssetDomain `json:"asset_domain"`
	Verdict      Verdict            `json:"verdict"`
	Confidence   ConfidenceLevel    `json:"confidence"`
	Evidence     *Evidence          `json:"evidence,omitempty"`
	TemporalRisk string             `json:"temporal_risk,omitempty"`
	Reason       string             `json:"reason,omitempty"` // populated for SKIPPED/INCONCLUSIVE
}

// MarkInconclusive shifts a row to an inconclusive state with a specific explanation.
func (r *ResourceCheck) MarkInconclusive(reason string) {
	if r == nil {
		return
	}
	r.Verdict = VerdictInconclusive
	r.Confidence = ConfidenceInconclusive
	r.Reason = reason
}

// ComplianceSummary provides high-level metrics for an evaluation run.
type ComplianceSummary struct {
	TotalAssets      int `json:"total_assets"`
	ExposedResources int `json:"exposed_resources"`
	Violations       int `json:"violations"`
}

// SkippedControl identifies a control that was ignored during the run.
type SkippedControl struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// ComplianceReport is the root aggregate of an evaluation execution.
type ComplianceReport struct {
	Run              RunInfo               `json:"run"`
	Summary          ComplianceSummary     `json:"summary"`
	SecurityState    SecurityState         `json:"security_state"`
	RiskSignals      risk.ThresholdItems   `json:"risk_signals,omitempty"`
	Findings         []Finding             `json:"findings"`
	ExceptedFindings []ExceptedFinding     `json:"excepted_findings,omitempty"`
	SkippedControls  []SkippedControl      `json:"skipped_controls,omitempty"`
	ExemptedAssets   []asset.ExemptedAsset `json:"exempted_assets,omitempty"`
	Metadata         Metadata              `json:"-"`
	Checks           []ResourceCheck       `json:"checks,omitempty"` // populated if --explain is used
}

// GetFindingByResource retrieves a finding for a specific control/asset pair, returning nil if not found.
func (r *ComplianceReport) GetFindingByResource(ctlID kernel.ControlID, astID asset.ID) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ControlID == ctlID && r.Findings[i].AssetID == astID {
			return &r.Findings[i]
		}
	}
	return nil
}
