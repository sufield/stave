package kernel

// SeverityOrder maps severity name to sort order (lower = higher priority).
// Single source of truth for severity ordering across all commands.
var SeverityOrder = map[string]int{
	"critical": 0,
	"high":     1,
	"medium":   2,
	"low":      3,
	"info":     4,
}

// SeverityWeight maps severity name to numeric weight for risk scoring.
// Single source of truth for severity weighting across all commands.
var SeverityWeight = map[string]float64{
	"critical": 4.0,
	"high":     3.0,
	"medium":   2.0,
	"low":      1.0,
}

// ParseSeverity normalizes a severity string to a canonical form.
// Returns "low" for unknown values.
func ParseSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "low"
	}
}
