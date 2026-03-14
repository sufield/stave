package upcoming

import (
	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/pkg/fp"
)

// newUpcomingFilter transforms raw input criteria into a validated domain filter.
func newUpcomingFilter(criteria FilterCriteria) (risk.FilterCriteria, error) {
	validated, err := risk.ValidateStatuses(criteria.Statuses)
	if err != nil {
		return risk.FilterCriteria{}, err
	}
	return risk.FilterCriteria{
		ControlIDs:   fp.ToSet(criteria.ControlIDs),
		AssetTypes:   fp.ToSet(criteria.AssetTypes),
		Statuses:     fp.ToSet(validated),
		MaxRemaining: criteria.DueWithin,
	}, nil
}
