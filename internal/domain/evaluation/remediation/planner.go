package remediation

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// Planner generates machine-readable remediation plans (Fix Plans) for violations.
type Planner interface {
	PlanFor(f Finding) *evaluation.RemediationPlan
}

// Specialist defines the interface for logic that handles a specific class of security risk.
type Specialist interface {
	CanHandle(class kernel.ControlClass) bool
	Plan(f Finding) *evaluation.RemediationPlan
}

// Ensure the internal planner implements the Planner interface.
var _ Planner = (*planner)(nil)

type planner struct {
	specialists []Specialist
}

// NewPlanner creates a remediation planner populated with default specialists.
func NewPlanner() Planner {
	return &planner{
		specialists: []Specialist{
			publicExposurePlanner{},
		},
	}
}

// PlanFor identifies the appropriate specialist to generate a remediation plan.
func (p *planner) PlanFor(f Finding) *evaluation.RemediationPlan {
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
func StablePlanID(controlID kernel.ControlID, assetID asset.ID) string {
	return policy.StableRemediationPlanID(controlID.String(), assetID.String())
}
