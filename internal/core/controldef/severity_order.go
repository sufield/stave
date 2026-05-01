package controldef

// SeverityOrder maps Severity to sort order (lower = higher priority).
// Single source of truth for severity ordering across all commands.
//
// The same ordering is also encoded in the Severity iota itself: a
// higher iota value means higher severity, so direct integer
// comparisons on the type also work and avoid a map lookup. This map
// is preserved for the call sites that already index by typed
// severity for stable, explicit ordering.
var SeverityOrder = map[Severity]int{
	SeverityCritical: 0,
	SeverityHigh:     1,
	SeverityMedium:   2,
	SeverityLow:      3,
	SeverityInfo:     4,
}

// SeverityWeight maps Severity to a numeric weight for risk scoring.
// Single source of truth for severity weighting across all commands.
var SeverityWeight = map[Severity]float64{
	SeverityCritical: 4.0,
	SeverityHigh:     3.0,
	SeverityMedium:   2.0,
	SeverityLow:      1.0,
}

// SeverityOrderOf returns the sort-order rank for a severity name.
// Convenience for boundary code that still carries severity as a
// string (DTO output, CLI flags). Returns the SeverityNone rank for
// unrecognized inputs, sorting them at the end.
func SeverityOrderOf(s string) int {
	parsed, err := ParseSeverity(s)
	if err != nil {
		return SeverityOrder[SeverityNone]
	}
	return SeverityOrder[parsed]
}

// SeverityWeightOf returns the numeric weight for a severity name.
// Convenience for boundary code; unrecognized inputs return 0.
func SeverityWeightOf(s string) float64 {
	parsed, err := ParseSeverity(s)
	if err != nil {
		return 0
	}
	return SeverityWeight[parsed]
}
