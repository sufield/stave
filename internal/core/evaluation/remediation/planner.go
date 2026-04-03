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
