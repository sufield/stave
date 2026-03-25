package upcoming

import (
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// NewUpcomingFilter transforms raw input criteria into a validated domain filter.
func NewUpcomingFilter(criteria FilterCriteria) (risk.ThresholdFilter, error) {
	validated, err := risk.ValidateStatuses(criteria.Statuses)
	if err != nil {
		return risk.ThresholdFilter{}, err
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

	var statusSet map[risk.ThresholdStatus]struct{}
	if len(validated) > 0 {
		statusSet = make(map[risk.ThresholdStatus]struct{}, len(validated))
		for _, item := range validated {
			statusSet[item] = struct{}{}
		}
	}

	return risk.ThresholdFilter{
		ControlIDs:   controlIDSet,
		AssetTypes:   assetTypeSet,
		Statuses:     statusSet,
		MaxRemaining: criteria.DueWithin,
	}, nil
}
