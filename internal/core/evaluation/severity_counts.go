package evaluation

import (
	policy "github.com/sufield/stave/internal/core/controldef"
)

// SeverityCounts tallies findings by their control severity tier.
// Convenient for status summaries, dashboards, and exit-code gating
// without rolling the same loop in every command.
type SeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// Total returns the sum of all severity buckets.
func (c SeverityCounts) Total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// CountBySeverity returns the per-severity tally of findings.
// Findings with an unrecognized severity are counted as Info so the
// total always matches len(findings) — silently dropping unknown
// severities would hide enum drift between catalog and engine.
func CountBySeverity(findings []Finding) SeverityCounts {
	var c SeverityCounts
	for i := range findings {
		switch findings[i].ControlSeverity {
		case policy.SeverityCritical:
			c.Critical++
		case policy.SeverityHigh:
			c.High++
		case policy.SeverityMedium:
			c.Medium++
		case policy.SeverityLow:
			c.Low++
		default:
			c.Info++
		}
	}
	return c
}
