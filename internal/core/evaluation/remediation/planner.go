package remediation

import (
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
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
func NewPlanner(gen ports.IdentityGenerator) *Planner {
	return &Planner{
		specialists: []Specialist{
			publicExposurePlanner{idGen: gen},
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

// StablePlanID generates a deterministic ID for a remediation plan based on the
// specific control and asset.
func StablePlanID(gen ports.IdentityGenerator, controlID kernel.ControlID, assetID asset.ID) policy.RemediationPlanID {
	return policy.StableRemediationPlanID(gen, controlID, assetID)
}
