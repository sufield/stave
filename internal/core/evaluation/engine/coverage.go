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
func (v CoverageValidator) IsSufficient(t *asset.Timeline) (string, bool) {
	if t == nil {
		return "no timeline data provided", false
	}

	stats := t.Stats()
	if !stats.HasCoverageData() {
		return "no observation snapshots found", false
	}

	// 1. Check total duration of observations
	if stats.CoverageSpan() < v.MinRequiredSpan {
		return fmt.Sprintf("observation span %s is less than required %s",
			stats.CoverageSpan(), v.MinRequiredSpan), false
	}

	// 2. Check for large gaps in the data
	if v.MaxAllowedGap > 0 && stats.MaxGap() > v.MaxAllowedGap {
		return fmt.Sprintf("maximum observation gap %s exceeds threshold %s",
			stats.MaxGap(), v.MaxAllowedGap), false
	}

	return "", true
}
