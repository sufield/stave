package remediation

import (
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
)

// Planner generates machine-readable remediation plans.
type Planner interface {
	PlanFor(f Finding) *evaluation.RemediationPlan
}

type specializedPlanner interface {
	CanHandle(class kernel.ControlClass) bool
	Plan(f Finding) *evaluation.RemediationPlan
}

type remediationPlanner struct {
	specialists []specializedPlanner
}

// NewPlanner creates the default remediation planner.
func NewPlanner() Planner {
	return &remediationPlanner{
		specialists: defaultSpecializedPlanners(),
	}
}

func (rp *remediationPlanner) PlanFor(f Finding) *evaluation.RemediationPlan {
	class := f.ControlID.Classify()
	for _, specialist := range rp.planners() {
		if specialist.CanHandle(class) {
			return specialist.Plan(f)
		}
	}
	return nil
}

func (rp *remediationPlanner) planners() []specializedPlanner {
	if len(rp.specialists) > 0 {
		return rp.specialists
	}
	// Guard for zero-value planner instances.
	return defaultSpecializedPlanners()
}

func defaultSpecializedPlanners() []specializedPlanner {
	return []specializedPlanner{
		s3PublicPlanner{},
	}
}

// StablePlanID returns a stable hash-derived fix-plan ID.
func StablePlanID(controlID kernel.ControlID, assetID asset.ID) string {
	return policy.StableRemediationPlanID(controlID.String(), assetID.String())
}
