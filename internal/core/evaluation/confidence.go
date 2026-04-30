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
//
// `requiredWindow <= 0` means the caller has no window-based signal
// to classify against — typically because the control omits
// max_unsafe_duration entirely. The previous behavior returned
// ConfidenceInconclusive in that case, which then degraded a
// verdict that had already been determined by other means (e.g. a
// state-based predicate that matched). Return ConfidenceHigh
// instead: the verdict's source of truth is the caller's
// predicate-evaluation chain, and Derive's job here is to *add*
// confidence from the window-coverage check, not subtract from
// the caller's existing certainty.
func (c ConfidenceCalculator) Derive(maxGap, requiredWindow time.Duration) ConfidenceLevel {
	if requiredWindow <= 0 {
		return ConfidenceHigh
	}
	if maxGap*time.Duration(c.HighMultiplier) <= requiredWindow {
		return ConfidenceHigh
	}
	if maxGap*time.Duration(c.MedMultiplier) <= requiredWindow {
		return ConfidenceMedium
	}
	return ConfidenceLow
}
