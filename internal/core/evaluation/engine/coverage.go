package engine

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// CoverageValidator defines the criteria for determining if a lifecycle
// has enough data for a confident PASS/VIOLATION decision.
type CoverageValidator struct {
	minRequiredSpan time.Duration
	maxAllowedGap   time.Duration
}

// NewCoverageValidator constructs a CoverageValidator. minSpan must
// be > maxGap; a maxGap that exceeds the minimum required span would
// always trip the gap check before the span check, leaving no
// observation pattern that could pass.
func NewCoverageValidator(minSpan, maxGap time.Duration) (*CoverageValidator, error) {
	if maxGap > 0 && minSpan <= maxGap {
		return nil, fmt.Errorf("engine.NewCoverageValidator: minSpan (%s) must exceed maxGap (%s)", minSpan, maxGap)
	}
	return &CoverageValidator{minRequiredSpan: minSpan, maxAllowedGap: maxGap}, nil
}

// IsSufficient checks if the provided lifecycle meets the coverage criteria.
// It returns (explanation, true) if coverage is sufficient.
// If coverage is insufficient, it returns (reason, false).
func (v CoverageValidator) IsSufficient(t *asset.ExposureLifecycle) (string, bool) {
	if t == nil {
		return "no lifecycle data provided", false
	}

	stats := t.Stats()
	if !stats.HasCoverageData() {
		return "no observation snapshots found", false
	}

	if v.auditWindowTooShort(stats) {
		return fmt.Sprintf("observation span %s is less than required %s",
			stats.CoverageSpan(), v.minRequiredSpan), false
	}

	if v.hasBlindSpots(stats) {
		return fmt.Sprintf("maximum observation gap %s exceeds threshold %s",
			stats.MaxGap(), v.maxAllowedGap), false
	}

	return "", true
}

// auditWindowTooShort reports whether the observation span is shorter than
// the minimum required for a confident evaluation.
func (v CoverageValidator) auditWindowTooShort(stats asset.ObservationStats) bool {
	return stats.CoverageSpan() < v.minRequiredSpan
}

// hasBlindSpots reports whether the data contains gaps large enough to
// miss a state change, making the evaluation unreliable.
func (v CoverageValidator) hasBlindSpots(stats asset.ObservationStats) bool {
	return v.maxAllowedGap > 0 && stats.MaxGap() > v.maxAllowedGap
}
