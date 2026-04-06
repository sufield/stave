package hygiene

import (
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
)

// CalculateTrend compares current risk metrics against metrics from a
// previous point in time. It is pure and has no external dependencies.
func CalculateTrend(current, previous appcontracts.SLAPosture) []evaluation.TrendMetric {
	return []evaluation.TrendMetric{
		{
			Name:     "Current violations",
			Current:  current.ActiveFindings,
			Previous: previous.ActiveFindings,
		},
		{
			Name:     "Upcoming overdue",
			Current:  current.SLABreaches,
			Previous: previous.SLABreaches,
		},
		{
			Name:     "Upcoming due soon",
			Current:  current.NearBreach,
			Previous: previous.NearBreach,
		},
		{
			Name:     "Upcoming total",
			Current:  current.PendingRemediations(),
			Previous: previous.PendingRemediations(),
		},
	}
}
