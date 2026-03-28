package evaluation

// TrendDirection classifies the direction of a posture change.
type TrendDirection int

const (
	// TrendStable indicates no change between periods.
	TrendStable TrendDirection = iota
	// TrendImproving indicates the metric moved in a favorable direction.
	TrendImproving
	// TrendDeclining indicates the metric moved in an unfavorable direction.
	TrendDeclining
)

// TrendMetric compares a named metric across two time windows.
// For security posture metrics, lower is better (fewer violations = improving).
type TrendMetric struct {
	Name     string `json:"name"`
	Current  int    `json:"current"`
	Previous int    `json:"previous"`
}

// Change returns the delta between current and previous values.
func (t TrendMetric) Change() int {
	return t.Current - t.Previous
}

// Direction returns whether this metric is improving, declining, or stable.
// Security posture metrics treat lower values as better.
func (t TrendMetric) Direction() TrendDirection {
	c := t.Change()
	if c == 0 {
		return TrendStable
	}
	if c < 0 {
		return TrendImproving
	}
	return TrendDeclining
}

// Symbol returns a human-readable arrow for the trend direction.
func (t TrendMetric) Symbol() string {
	switch t.Direction() {
	case TrendImproving:
		return "↓ "
	case TrendDeclining:
		return "↑ "
	default:
		return ""
	}
}
