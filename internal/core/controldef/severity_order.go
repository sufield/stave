package controldef

var severityOrder = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// SeverityOrderOf returns the sort-order rank for a severity name.
func SeverityOrderOf(s string) int {
	parsed, err := ParseSeverity(s)
	if err != nil {
		return severityOrder[SeverityNone]
	}
	return severityOrder[parsed]
}
