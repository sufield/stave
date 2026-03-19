package upcoming

import (
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/domain/kernel"
)

// newUpcomingFilter transforms raw input criteria into a validated domain filter.
func newUpcomingFilter(criteria FilterCriteria) (risk.FilterCriteria, error) {
	validated, err := risk.ValidateStatuses(criteria.Statuses)
	if err != nil {
		return risk.FilterCriteria{}, err
	}
	var controlIDSet map[kernel.ControlID]struct{}
	if len(criteria.ControlIDs) > 0 {
		controlIDSet = make(map[kernel.ControlID]struct{}, len(criteria.ControlIDs))
		for _, item := range criteria.ControlIDs {
			controlIDSet[item] = struct{}{}
		}
	}

	var assetTypeSet map[kernel.AssetType]struct{}
	if len(criteria.AssetTypes) > 0 {
		assetTypeSet = make(map[kernel.AssetType]struct{}, len(criteria.AssetTypes))
		for _, item := range criteria.AssetTypes {
			assetTypeSet[item] = struct{}{}
		}
	}

	var statusSet map[risk.Status]struct{}
	if len(validated) > 0 {
		statusSet = make(map[risk.Status]struct{}, len(validated))
		for _, item := range validated {
			statusSet[item] = struct{}{}
		}
	}

	return risk.FilterCriteria{
		ControlIDs:   controlIDSet,
		AssetTypes:   assetTypeSet,
		Statuses:     statusSet,
		MaxRemaining: criteria.DueWithin,
	}, nil
}
