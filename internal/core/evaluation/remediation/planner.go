package remediation

import (
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Specialist generates a remediation plan for a specific class of security risk.
type Specialist interface {
	Plan(f Finding) *evaluation.RemediationPlan
}

// Planner generates machine-readable remediation plans (Fix Plans) for violations.
type Planner struct {
	specialists map[kernel.ControlClass]Specialist
}

// Compile-time check: Planner satisfies FindingEnricher.
var _ FindingEnricher = (*Planner)(nil)

// NewPlanner creates a remediation planner populated with default specialists.
func NewPlanner() *Planner {
	p := &Planner{
		specialists: make(map[kernel.ControlClass]Specialist),
	}
	p.Register(kernel.ClassPublicExposure, publicExposurePlanner{})
	return p
}

// Register binds a specialist to a control class.
func (p *Planner) Register(class kernel.ControlClass, s Specialist) {
	p.specialists[class] = s
}

// PlanFor returns a remediation plan for the finding's control class,
// or nil if no specialist is registered for that class.
//
//nolint:gocritic // hugeParam: PlanFor is an interface boundary — callers pass by value
func (p *Planner) PlanFor(f Finding) *evaluation.RemediationPlan {
	if s, ok := p.specialists[f.ControlID.Classify()]; ok {
		return s.Plan(f)
	}
	return nil
}

// EnrichFindings combines raw violations with their remediation specs and plans.
func (p *Planner) EnrichFindings(result *evaluation.ComplianceReport) []Finding {
	enriched := make([]Finding, len(result.Findings))
	for i := range result.Findings {
		f := &result.Findings[i]
		findingWithPlan := Finding{
			Finding:         *f,
			RemediationSpec: resolveSpec(f),
		}
		findingWithPlan.RemediationPlan = p.PlanFor(findingWithPlan)
		parameterizeCommand(&findingWithPlan)
		enriched[i] = findingWithPlan
	}
	return enriched
}

// parameterizeCommand substitutes placeholder tokens in the
// RemediationSpec.Action prose CLI with asset-specific values and
// stores the result on RemediationPlan.Command. The RemediationSpec
// template itself is never mutated — it stays reusable across assets.
// See docs/product/metrics.md § Metric 4.
func parameterizeCommand(f *Finding) {
	if f.RemediationSpec.Action == "" {
		return
	}
	if f.RemediationPlan == nil {
		// Construct a minimal plan to carry the parameterized command
		// when no class-specific plan exists. Preserves the
		// remediation data surface without requiring every class to
		// register a Specialist.
		f.RemediationPlan = &evaluation.RemediationPlan{
			Target: evaluation.RemediationTarget{
				AssetID:   f.AssetID,
				AssetType: f.AssetType,
			},
		}
	}
	syntheticAsset := asset.Asset{ID: f.AssetID, Type: f.AssetType, Vendor: f.AssetVendor}
	f.RemediationPlan.Command = FormatRemediationAction(f.RemediationSpec.Action, syntheticAsset)
}
