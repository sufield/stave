package remediation

import (
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
func (p *Planner) PlanFor(f Finding) *evaluation.RemediationPlan {
	if s, ok := p.specialists[f.ControlID.Classify()]; ok {
		return s.Plan(f)
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
