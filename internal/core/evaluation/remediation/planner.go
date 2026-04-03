package remediation

import (
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Specialist defines the interface for logic that handles a specific class of security risk.
type Specialist interface {
	CanHandle(class kernel.ControlClass) bool
	Plan(f Finding) *evaluation.RemediationPlan
}

// Planner generates machine-readable remediation plans (Fix Plans) for violations.
type Planner struct {
	specialists []Specialist
}

// Compile-time check: Planner satisfies FindingEnricher.
var _ FindingEnricher = (*Planner)(nil)

// NewPlanner creates a remediation planner populated with default specialists.
func NewPlanner() *Planner {
	return &Planner{
		specialists: []Specialist{
			publicExposurePlanner{},
		},
	}
}

// PlanFor identifies the appropriate specialist to generate a remediation plan.
func (p *Planner) PlanFor(f Finding) *evaluation.RemediationPlan {
	class := f.ControlID.Classify()
	for _, s := range p.specialists {
		if s.CanHandle(class) {
			return s.Plan(f)
		}
	}
	return nil
}

// EnrichFindings combines raw violations with their remediation specs and plans.
func (p *Planner) EnrichFindings(result evaluation.Result) []Finding {
	enriched := make([]Finding, len(result.Findings))
	for i, f := range result.Findings {
		item := Finding{
			Finding:         f,
			RemediationSpec: resolveSpec(f),
		}
		item.RemediationPlan = p.PlanFor(item)
		enriched[i] = item
	}
	return enriched
}
