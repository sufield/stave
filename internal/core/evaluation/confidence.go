package evaluation

import "time"

// Default confidence multipliers: HIGH when maxGap <= 25% of window (4x),
// MEDIUM when maxGap <= 50% of window (2x).
const (
	DefaultConfidenceHighMultiplier = 4
	DefaultConfidenceMedMultiplier  = 2
)

// ConfidenceCalculator classifies evaluation confidence based on the ratio
// of the largest observation gap to the required evaluation window.
// Pass it through the engine rather than using mutable global state.
type ConfidenceCalculator struct {
	HighMultiplier int // maxGap * HighMultiplier <= window → HIGH
	MedMultiplier  int // maxGap * MedMultiplier <= window → MEDIUM
}

// DefaultConfidenceCalculator returns the standard confidence thresholds.
func DefaultConfidenceCalculator() ConfidenceCalculator {
	return ConfidenceCalculator{
		HighMultiplier: DefaultConfidenceHighMultiplier,
		MedMultiplier:  DefaultConfidenceMedMultiplier,
	}
}

// Derive classifies confidence based on the largest observation gap
// relative to the required evaluation window.
func (c ConfidenceCalculator) Derive(maxGap, requiredWindow time.Duration) ConfidenceLevel {
	if requiredWindow <= 0 {
		return ConfidenceInconclusive
	}
	if maxGap*time.Duration(c.HighMultiplier) <= requiredWindow {
		return ConfidenceHigh
	}
	if maxGap*time.Duration(c.MedMultiplier) <= requiredWindow {
		return ConfidenceMedium
	}
	return ConfidenceLow
}
