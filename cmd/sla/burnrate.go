package sla

// BurnRateStatus classifies an SLA burn-rate value into the three
// regions the simulate / monitor renderers care about: within
// budget, approaching the deadline, and breached. Centralised here
// so the burn-rate threshold semantics live in one place rather
// than inline (rate >= 1.0) / (rate >= 0.7) probes scattered across
// renderers.
type BurnRateStatus int

const (
	// BurnRateWithin marks burn rates below the approaching
	// threshold — the finding is on track to remediate before its
	// SLA deadline.
	BurnRateWithin BurnRateStatus = iota
	// BurnRateApproaching marks burn rates between the approaching
	// and breached thresholds — the finding is at risk of breaching
	// its SLA without intervention.
	BurnRateApproaching
	// BurnRateBreached marks burn rates at or above 1.0 — the
	// finding has already crossed its SLA deadline.
	BurnRateBreached
)

// Burn-rate threshold constants. Centralised so a future tweak to
// the "approaching" cut-off lands in one place. The breached
// threshold is fixed at 1.0 by definition (burn rate ≥ deadline).
const (
	BreachedThreshold    = 1.0
	ApproachingThreshold = 0.7
)

// ClassifyBurnRate maps a burn-rate float to the BurnRateStatus
// region it falls into. Replaces the inline (rate >= 1.0) /
// (rate >= 0.7) probes in simulate.go.
func ClassifyBurnRate(rate float64) BurnRateStatus {
	switch {
	case rate >= BreachedThreshold:
		return BurnRateBreached
	case rate >= ApproachingThreshold:
		return BurnRateApproaching
	default:
		return BurnRateWithin
	}
}

// IsBreached reports whether the status is at or past the breached
// threshold.
func (s BurnRateStatus) IsBreached() bool { return s == BurnRateBreached }

// IsApproaching reports whether the status sits between the
// approaching and breached thresholds.
func (s BurnRateStatus) IsApproaching() bool { return s == BurnRateApproaching }

// IsWithin reports whether the status is below the approaching
// threshold (on track).
func (s BurnRateStatus) IsWithin() bool { return s == BurnRateWithin }
