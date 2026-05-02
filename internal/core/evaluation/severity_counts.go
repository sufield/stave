package evaluation

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
	buckets := map[string]*int{}
	var c SeverityCounts
	buckets["critical"] = &c.Critical
	buckets["high"] = &c.High
	buckets["medium"] = &c.Medium
	buckets["low"] = &c.Low
	buckets["info"] = &c.Info
	for i := range findings {
		bucket := findings[i].ControlSeverity.BucketName()
		if ptr, ok := buckets[bucket]; ok {
			*ptr++
		} else {
			c.Info++
		}
	}
	return c
}
