package remediation

import (
	"errors"
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
)

// ErrFindingNotFound is returned when no finding matches the requested control+asset pair.
var ErrFindingNotFound = errors.New("finding not found")

// BuildFindingDetail composes evidence, predicate traces, and remediation plans
// into a comprehensive detail view for a specific violation.
// The gen parameter assigns stable IDs to remediation plans at this boundary.
func BuildFindingDetail(r *evaluation.Result, req evaluation.FindingDetailRequest, gen ports.IdentityGenerator) (*evaluation.FindingDetail, error) {
	violation := r.FindFinding(req.ControlID, req.AssetID)
	if violation == nil {
		return nil, fmt.Errorf("%w: control %q asset %q", ErrFindingNotFound, req.ControlID, req.AssetID)
	}

	// 1. Resolve Control Definition (Metadata Source)
	var ctl *policy.ControlDefinition
	if req.Controls != nil {
		ctl = req.Controls.FindByID(violation.ControlID)
	}

	// 2. Initialize the Detail View
	detail := &evaluation.FindingDetail{
		Evidence:     violation.Evidence,
		PostureDrift: violation.PostureDrift,
		Control:      buildControlSummary(ctl, violation),
		Asset: evaluation.FindingAssetSummary{
			ID:         violation.AssetID,
			Type:       violation.AssetType,
			Vendor:     violation.AssetVendor,
			ObservedAt: violation.Evidence.LastSeenUnsafeAt,
		},
	}

	// 3. Optional: Build Predicate Trace
	if req.TraceBuilder != nil {
		detail.Trace = req.TraceBuilder.BuildTrace(evaluation.TraceRequest{
			Control:    ctl,
			AssetID:    req.AssetID,
			Snapshots:  req.Snapshots,
			TargetTime: violation.Evidence.LastSeenUnsafeAt,
		})
	}

	// 4. Map and Plan Remediation
	spec := resolveSpec(*violation)
	detail.Remediation = &spec

	enriched := Finding{
		Finding:         *violation,
		RemediationSpec: spec,
	}
	plan := NewPlanner().PlanFor(enriched)
	if plan != nil && gen != nil {
		plan.ID = policy.StableRemediationPlanID(gen, violation.ControlID, violation.AssetID)
	}
	detail.RemediationPlan = plan

	// 5. Generate Instructional Next Steps
	detail.NextSteps = buildNextSteps(detail)

	return detail, nil
}

func buildControlSummary(ctl *policy.ControlDefinition, f *evaluation.Finding) evaluation.FindingControlSummary {
	if ctl != nil {
		var exp *policy.Exposure
		if ctl.Exposure != nil {
			exp = &policy.Exposure{
				Type:           ctl.Exposure.Type,
				PrincipalScope: ctl.Exposure.PrincipalScope,
			}
		}

		return evaluation.FindingControlSummary{
			ID:          ctl.ID,
			Name:        ctl.Name,
			Description: ctl.Description,
			Severity:    ctl.Severity,
			Domain:      ctl.Domain,
			Type:        ctl.Type,
			ScopeTags:   ctl.ScopeTags,
			Compliance:  policy.ComplianceMapping(ctl.Compliance),
			Exposure:    exp,
		}
	}

	// Fallback: Use denormalized data stored in the finding if ctl definition is missing
	return evaluation.FindingControlSummary{
		ID:          f.ControlID,
		Name:        f.ControlName,
		Description: f.ControlDescription,
		Severity:    f.ControlSeverity,
		Compliance:  f.ControlCompliance,
	}
}

func buildNextSteps(d *evaluation.FindingDetail) []string {
	steps := make([]string, 0, 3)

	if d.Remediation.Actionable() {
		steps = append(steps, "Apply the remediation action described above.")
	}

	steps = append(steps, "Re-run `stave apply` after applying changes to verify remediation.")

	traceCmd := fmt.Sprintf("stave trace --control %s", d.Control.ID)
	steps = append(steps, fmt.Sprintf("Run `%s` against a new snapshot to confirm the predicate no longer matches.", traceCmd))

	return steps
}
