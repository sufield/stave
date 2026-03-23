package hygiene

import (
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
)

// CalculateTrend compares current risk metrics against metrics from a
// previous point in time. It is pure and has no external dependencies.
func CalculateTrend(current, previous appcontracts.RiskStats) []evaluation.TrendMetric {
	return []evaluation.TrendMetric{
		{
			Name:     "Current violations",
			Current:  current.CurrentViolations,
			Previous: previous.CurrentViolations,
		},
		{
			Name:     "Upcoming overdue",
			Current:  current.Overdue,
			Previous: previous.Overdue,
		},
		{
			Name:     "Upcoming due soon",
			Current:  current.DueSoon,
			Previous: previous.DueSoon,
		},
		{
			Name:     "Upcoming total",
			Current:  current.UpcomingTotal(),
			Previous: previous.UpcomingTotal(),
		},
	}
}
