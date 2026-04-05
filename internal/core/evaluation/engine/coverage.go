package engine

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// CoverageValidator defines the criteria for determining if a timeline
// has enough data for a confident PASS/VIOLATION decision.
type CoverageValidator struct {
	MinRequiredSpan time.Duration
	MaxAllowedGap   time.Duration
}

// IsSufficient checks if the provided timeline meets the coverage criteria.
// It returns (explanation, true) if coverage is sufficient.
// If coverage is insufficient, it returns (reason, false).
func (v CoverageValidator) IsSufficient(t *asset.ExposureLifecycle) (string, bool) {
	if t == nil {
		return "no timeline data provided", false
	}

	stats := t.Stats()
	if !stats.HasCoverageData() {
		return "no observation snapshots found", false
	}

	if v.auditWindowTooShort(stats) {
		return fmt.Sprintf("observation span %s is less than required %s",
			stats.CoverageSpan(), v.MinRequiredSpan), false
	}

	if v.hasBlindSpots(stats) {
		return fmt.Sprintf("maximum observation gap %s exceeds threshold %s",
			stats.MaxGap(), v.MaxAllowedGap), false
	}

	return "", true
}

// auditWindowTooShort reports whether the observation span is shorter than
// the minimum required for a confident evaluation.
func (v CoverageValidator) auditWindowTooShort(stats asset.ObservationStats) bool {
	return stats.CoverageSpan() < v.MinRequiredSpan
}

// hasBlindSpots reports whether the data contains gaps large enough to
// miss a state change, making the evaluation unreliable.
func (v CoverageValidator) hasBlindSpots(stats asset.ObservationStats) bool {
	return v.MaxAllowedGap > 0 && stats.MaxGap() > v.MaxAllowedGap
}
