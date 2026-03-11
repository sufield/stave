package remediation

import (
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
)

// ErrFindingNotFound is returned when no finding matches the requested control+asset pair.
var ErrFindingNotFound = errors.New("finding not found")

// BuildFindingDetail composes violation evidence, predicate trace, and
// remediation into a single FindingDetail for the requested control+asset pair.
func BuildFindingDetail(r *evaluation.Result, req evaluation.FindingDetailRequest) (*evaluation.FindingDetail, error) {
	violation := r.FindFinding(req.ControlID, req.AssetID)
	if violation == nil {
		return nil, fmt.Errorf("%w: control %q asset %q", ErrFindingNotFound, req.ControlID, req.AssetID)
	}

	// The finding knows its own control — resolve it through the provider.
	var ctl *policy.ControlDefinition
	if req.Controls != nil {
		ctl = req.Controls.FindByID(violation.ControlID)
	}

	detail := &evaluation.FindingDetail{
		Evidence: violation.Evidence,
	}

	detail.Control = buildControlSummary(ctl, violation)

	detail.Asset = evaluation.FindingAssetSummary{
		ID:         violation.AssetID,
		Type:       string(violation.AssetType),
		Vendor:     string(violation.AssetVendor),
		ObservedAt: violation.Evidence.LastSeenUnsafeAt,
	}

	if req.TraceBuilder != nil {
		detail.Trace = req.TraceBuilder.BuildTrace(ctl, req.AssetID, req.Snapshots, violation.Evidence.LastSeenUnsafeAt)
	}

	mapper := NewMapper()
	mit := mapper.MapFinding(*violation)
	detail.Remediation = &mit

	enriched := Finding{
		Finding:         *violation,
		RemediationSpec: mit,
	}
	detail.RemediationPlan = NewPlanner().PlanFor(enriched)

	detail.PostureDrift = violation.PostureDrift

	detail.NextSteps = buildFindingNextSteps(detail)

	return detail, nil
}

func buildControlSummary(ctl *policy.ControlDefinition, violation *evaluation.Finding) evaluation.FindingControlSummary {
	if ctl != nil {
		var exposure *policy.Exposure
		if ctl.Exposure != nil {
			exposure = &policy.Exposure{
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
			Type:        ctl.Type.String(),
			ScopeTags:   ctl.ScopeTags,
			Compliance:  policy.ComplianceMapping(ctl.Compliance),
			Exposure:    exposure,
		}
	}

	return evaluation.FindingControlSummary{
		ID:          violation.ControlID,
		Name:        violation.ControlName,
		Description: violation.ControlDescription,
		Severity:    violation.ControlSeverity,
		Compliance:  violation.ControlCompliance,
	}
}

func buildFindingNextSteps(detail *evaluation.FindingDetail) []string {
	steps := make([]string, 0, 3)
	if detail.Remediation.Actionable() {
		steps = append(steps, "Apply the remediation action described above.")
	}
	steps = append(steps, "Re-run `stave apply` after applying changes to verify remediation.")
	steps = append(steps, "Run `stave trace --control "+detail.Control.ID.String()+"` against a new snapshot to confirm the predicate no longer matches.")
	return steps
}
