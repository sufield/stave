package kernel

import (
	"encoding/json"
)

// ScoreBand classifies an ExposureScore into a coarse severity tier.
// Centralised so renderers and CLI output share one band-mapping
// definition instead of each open-coding the >0.85 / >0.5 cliffs.
type ScoreBand string

// Recognised score bands. Boundaries (BandCritical at 0.85, etc.)
// live as the constants below — change the cutoff once and every
// caller's classification follows.
const (
	BandUnscored     ScoreBand = "unscored"
	BandSafe         ScoreBand = "safe"
	BandInfo         ScoreBand = "info"
	BandWarning      ScoreBand = "warning"
	BandCritical     ScoreBand = "critical"
	BandCatastrophic ScoreBand = "catastrophic"
)

// Score-band cutoffs. Stored as constants so changing the
// "critical" line from 0.85 to a different value is a single-line
// edit. The bands divide the [0, 1+] continuum used by
// ExposureScore (and may exceed 1.0 when chain bonuses stack).
const (
	scoreBandInfoMin         = 0.10
	scoreBandWarningMin      = 0.40
	scoreBandCriticalMin     = 0.85
	scoreBandCatastrophicMin = 1.00
)

// ExposureScore quantifies how exposed a finding is. The numeric
// value is the underlying score; the type adds semantic accessors
// (IsScored, Band) so call sites don't open-code "0 means unscored"
// or band cutoffs.
//
// Zero value semantics: ExposureScore(0) is "unscored", matching the
// existing convention in core/evaluation. Use IsScored() to
// distinguish between a deliberate zero score and a finding that
// hasn't been through the enrichment pass yet.
//
// Comparison: Go does not allow `score > 0.5` once the type is
// distinct from float64. Call sites either compare via Value() or
// wrap the literal: `score > kernel.ExposureScore(0.5)`. The cost
// of the extra cast is the type-safety win that two ExposureScore
// values can no longer be silently interchanged with raw floats from
// other domains.
type ExposureScore float64

// Value returns the underlying float64.
func (s ExposureScore) Value() float64 { return float64(s) }

// IsScored reports whether the finding has been through the
// enrichment pass that assigns a non-zero score. An ExposureScore
// of exactly 0 means "not yet scored"; any non-zero value (positive
// or negative — negatives are not expected but kept distinct) is a
// scored finding.
func (s ExposureScore) IsScored() bool { return s != 0 }

// IsEmpty is an alias for !IsScored, matching the pattern other
// kernel value types expose so callers can use a uniform
// "is the field set?" predicate.
func (s ExposureScore) IsEmpty() bool { return s == 0 }

// Band classifies the score into a coarse severity tier. Boundary
// constants (scoreBandInfoMin, etc.) live in this file so a future
// adjustment ("critical now starts at 0.80") is a single-line
// change.
func (s ExposureScore) Band() ScoreBand {
	v := float64(s)
	switch {
	case !s.IsScored():
		return BandUnscored
	case v >= scoreBandCatastrophicMin:
		return BandCatastrophic
	case v >= scoreBandCriticalMin:
		return BandCritical
	case v >= scoreBandWarningMin:
		return BandWarning
	case v >= scoreBandInfoMin:
		return BandInfo
	default:
		return BandSafe
	}
}

// MarshalJSON preserves the numeric wire form so consumers that
// expect a JSON number (dashboards, downstream gates) keep working.
func (s ExposureScore) MarshalJSON() ([]byte, error) {
	return json.Marshal(float64(s))
}

// UnmarshalJSON parses a JSON number.
func (s *ExposureScore) UnmarshalJSON(b []byte) error {
	var v float64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*s = ExposureScore(v)
	return nil
}
