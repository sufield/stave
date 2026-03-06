package engine

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/asset"
)

// CoverageValidator determines whether timeline continuity is sufficient
// for a confident PASS/VIOLATION decision.
type CoverageValidator struct {
	Timeline         *asset.Timeline
	RequiredCoverage time.Duration
	MaxGapThreshold  time.Duration
	CoverageReason   string
}

// Validate returns (reason, inconclusive). When inconclusive is true,
// reason explains why the decision cannot be made confidently.
func (v CoverageValidator) Validate() (string, bool) {
	if v.Timeline == nil {
		return "no coverage data", true
	}

	stats := v.Timeline.Stats()
	if !stats.HasCoverageData() {
		return "no coverage data", true
	}

	if stats.CoverageSpan() < v.RequiredCoverage {
		return v.CoverageReason, true
	}

	if v.MaxGapThreshold > 0 && stats.MaxGap() > v.MaxGapThreshold {
		return fmt.Sprintf("observation gap exceeds %s threshold", v.MaxGapThreshold), true
	}

	return "", false
}
