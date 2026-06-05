package controldef

var severityOrder = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// severityOrderUnknown ranks unknown or empty severities strictly after
// the least severe mapped level (Info, rank 4), so garbage input never
// collides with Critical's rank (0) and sorts as the least severe.
const severityOrderUnknown = 5

// SeverityOrderOf returns the sort-order rank for a severity name.
func SeverityOrderOf(s string) int {
	parsed, err := ParseSeverity(s)
	if err != nil {
		return severityOrderUnknown
	}
	rank, ok := severityOrder[parsed]
	if !ok {
		// Parsed but unmapped (e.g. SeverityNone from an empty or
		// "none" input): rank as least severe, never as Critical.
		return severityOrderUnknown
	}
	return rank
}
