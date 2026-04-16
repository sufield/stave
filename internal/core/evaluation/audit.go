package evaluation

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/evidence"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/util/sets"
)

// ConfidenceLevel quantifies the certainty of an evaluation result.
type ConfidenceLevel string

const (
	ConfidenceHigh         ConfidenceLevel = "HIGH"
	ConfidenceMedium       ConfidenceLevel = "MEDIUM"
	ConfidenceLow          ConfidenceLevel = "LOW"
	ConfidenceInconclusive ConfidenceLevel = "INCONCLUSIVE"
)

// SecurityState classifies the high-level security posture of the environment.
type SecurityState string

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

// Verdict represents the final outcome of a security control check against a resource.
type Verdict string

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
	Reason       string             `json:"reason,omitempty"`
}

// MarkInconclusive shifts a check to an inconclusive state with a specific explanation.
func (c *ResourceCheck) MarkInconclusive(reason string) {
	if c == nil {
		return
	}
	c.Verdict = VerdictInconclusive
	c.Confidence = ConfidenceInconclusive
	c.Reason = reason
}

// ComplianceSummary provides high-level metrics for an evaluation run.
type ComplianceSummary struct {
	TotalAssets                 int                  `json:"total_assets"`
	ExposedResources            int                  `json:"exposed_resources"`
	Violations                  int                  `json:"violations"`
	FrameworkReadiness          []FrameworkReadiness `json:"framework_readiness,omitempty"`
	FrameworkCitationsSatisfied int                  `json:"framework_citations_satisfied,omitempty"`
	SuperFix                    *SuperFix            `json:"super_fix,omitempty"`
	NearbyFrameworks            []NearbyFramework    `json:"nearby_frameworks,omitempty"`
}

// FrameworkReadiness shows per-framework compliance scores.
type FrameworkReadiness struct {
	Framework        string `json:"framework"`
	TotalControls    int    `json:"total_controls"`
	PassingControls  int    `json:"passing_controls"`
	ReadinessPercent int    `json:"readiness_percent"`
}

// SuperFix identifies the single highest-impact remediation —
// the violated control that satisfies the most framework citations.
type SuperFix struct {
	ControlID      kernel.ControlID `json:"control_id"`
	FrameworkCount int              `json:"framework_count"`
	Frameworks     []string         `json:"frameworks"`
	CitationsFixed int              `json:"citations_fixed"`
}

// NearbyFramework is a framework the user did not request but is
// nearly compliant with based on the evaluated controls.
type NearbyFramework struct {
	Framework        string `json:"framework"`
	ReadinessPercent int    `json:"readiness_percent"`
	GapCount         int    `json:"gap_count"`
}

// CalculateReadiness computes per-framework readiness scores from
// the evaluated controls and findings. Each framework is scored
// independently: readiness = passing / total × 100.
func (r *ComplianceReport) CalculateReadiness(frameworks []string, allControlIDs []kernel.ControlID, controlCompliance map[kernel.ControlID]map[string]string) {
	if len(frameworks) == 0 {
		return
	}

	failingIDs := sets.New[kernel.ControlID]()
	for i := range r.Findings {
		failingIDs.Add(r.Findings[i].ControlID)
	}

	var totalCitations int
	readiness := make([]FrameworkReadiness, 0, len(frameworks))

	for _, fw := range frameworks {
		total := 0
		passing := 0
		for _, ctlID := range allControlIDs {
			cc, ok := controlCompliance[ctlID]
			if !ok {
				continue
			}
			if _, hasFW := cc[fw]; !hasFW {
				continue
			}
			total++
			totalCitations++
			if !failingIDs.Contains(ctlID) {
				passing++
			}
		}
		pct := 100
		if total > 0 {
			pct = passing * 100 / total
		}
		readiness = append(readiness, FrameworkReadiness{
			Framework:        fw,
			TotalControls:    total,
			PassingControls:  passing,
			ReadinessPercent: pct,
		})
	}

	r.Summary.FrameworkReadiness = readiness
	r.Summary.FrameworkCitationsSatisfied = totalCitations

	// Super-Fix: find the violated control covering the most frameworks.
	r.Summary.SuperFix = computeSuperFix(failingIDs, controlCompliance, frameworks)

	// Nearby frameworks: check all frameworks for near-readiness.
	requestedSet := sets.New[string](frameworks...)
	r.Summary.NearbyFrameworks = computeNearbyFrameworks(failingIDs, allControlIDs, controlCompliance, requestedSet)
}

func computeSuperFix(failingIDs sets.Set[kernel.ControlID], controlCompliance map[kernel.ControlID]map[string]string, frameworks []string) *SuperFix {
	fwSet := sets.New[string](frameworks...)

	var best *SuperFix
	for ctlID := range failingIDs {
		cc, ok := controlCompliance[ctlID]
		if !ok {
			continue
		}
		var fws []string
		for fw := range cc {
			if fwSet.Contains(fw) {
				fws = append(fws, fw)
			}
		}
		if len(fws) > 0 && (best == nil || len(fws) > best.FrameworkCount) {
			best = &SuperFix{
				ControlID:      ctlID,
				FrameworkCount: len(fws),
				Frameworks:     fws,
				CitationsFixed: len(fws),
			}
		}
	}
	return best
}

func computeNearbyFrameworks(failingIDs sets.Set[kernel.ControlID], allControlIDs []kernel.ControlID, controlCompliance map[kernel.ControlID]map[string]string, requestedSet sets.Set[string]) []NearbyFramework {
	// Discover all frameworks across all controls.
	allFWs := sets.New[string]()
	for _, cc := range controlCompliance {
		for fw := range cc {
			if !requestedSet.Contains(fw) {
				allFWs.Add(fw)
			}
		}
	}

	var nearby []NearbyFramework
	for fw := range allFWs {
		total := 0
		passing := 0
		for _, ctlID := range allControlIDs {
			cc, ok := controlCompliance[ctlID]
			if !ok {
				continue
			}
			if _, has := cc[fw]; !has {
				continue
			}
			total++
			if !failingIDs.Contains(ctlID) {
				passing++
			}
		}
		if total == 0 {
			continue
		}
		pct := passing * 100 / total
		gap := total - passing
		// Only report frameworks with >= 80% readiness.
		if pct >= 80 {
			nearby = append(nearby, NearbyFramework{
				Framework:        fw,
				ReadinessPercent: pct,
				GapCount:         gap,
			})
		}
	}
	return nearby
}

// SkippedControl identifies a control that was ignored during the run.
type SkippedControl struct {
	ControlID   kernel.ControlID `json:"control_id"`
	ControlName string           `json:"control_name"`
	Reason      string           `json:"reason"`
}

// ComplianceReport is the root aggregate of an evaluation execution.
type ComplianceReport struct {
	Run                  RunInfo                      `json:"run"`
	Summary              ComplianceSummary            `json:"summary"`
	SecurityState        SecurityState                `json:"security_state"`
	RiskSignals          risk.ThresholdItems          `json:"risk_signals,omitempty"`
	Findings             []Finding                    `json:"findings"`
	ChainFindings        []risk.CompoundFinding       `json:"chain_findings,omitempty"`
	AttackStageSummary   map[string]string            `json:"attack_stage_summary,omitempty"`
	TopExposures         []risk.ExposureRank          `json:"top_exposures,omitempty"`
	ExceptedFindings     []ExceptedFinding            `json:"excepted_findings,omitempty"`
	AcknowledgedFindings []policy.AcknowledgedFinding `json:"acknowledged_findings,omitempty"`
	SkippedControls      []SkippedControl             `json:"skipped_controls,omitempty"`
	ExemptedAssets       []asset.ExemptedAsset        `json:"exempted_assets,omitempty"`
	Metadata             Metadata                     `json:"-"`
	Checks               []ResourceCheck              `json:"checks,omitempty"`
	EvidencePackage      *evidence.EvidencePackage    `json:"evidence_package,omitempty"`
}

// GetFindingByResource retrieves a finding for a specific control/asset pair.
func (r *ComplianceReport) GetFindingByResource(ctlID kernel.ControlID, astID asset.ID) *Finding {
	for i := range r.Findings {
		if r.Findings[i].ControlID == ctlID && r.Findings[i].AssetID == astID {
			return &r.Findings[i]
		}
	}
	return nil
}
