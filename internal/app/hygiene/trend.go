package hygiene

// CalculateTrend compares current risk metrics against metrics from a
// previous point in time. It is pure and has no external dependencies.
func CalculateTrend(current, previous RiskStats) []TrendMetric {
	return []TrendMetric{
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
			Current:  current.UpcomingTotal,
			Previous: previous.UpcomingTotal,
		},
	}
}
