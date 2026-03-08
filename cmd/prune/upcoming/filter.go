package upcoming

import (
	"time"

	"github.com/sufield/stave/internal/domain/evaluation/risk"
	"github.com/sufield/stave/internal/pkg/fp"
)

func newUpcomingFilter(criteria UpcomingFilterCriteria) (risk.FilterCriteria, error) {
	validated, err := risk.ValidateStatuses(criteria.Statuses)
	if err != nil {
		return risk.FilterCriteria{}, err
	}
	var maxRemaining = derefDuration(criteria.DueWithin)
	return risk.FilterCriteria{
		ControlIDs:   fp.ToSet(criteria.ControlIDs),
		AssetTypes:   fp.ToSet(criteria.AssetTypes),
		Statuses:     fp.ToSet(validated),
		MaxRemaining: maxRemaining,
	}, nil
}

func derefDuration(d *time.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return *d
}
