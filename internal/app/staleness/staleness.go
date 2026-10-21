// Package staleness detects observation collection gaps by comparing
// the most recent snapshot timestamp against a freshness threshold.
// Produces a COLLECTION_STALENESS finding when data is too old.
package staleness

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// StalenessHours encapsulates an observation staleness duration in hours.
type StalenessHours float64

// Value returns the raw float64 hours value.
func (sh StalenessHours) Value() float64 {
	return float64(sh)
}

// Days returns the duration in days (hours / 24).
func (sh StalenessHours) Days() float64 {
	return float64(sh) / 24.0
}

// Result holds the staleness check outcome.
type Result struct {
	MostRecent   time.Time      `json:"most_recent_snapshot"`
	Staleness    time.Duration  `json:"-"`
	Threshold    time.Duration  `json:"-"`
	Gap          time.Duration  `json:"-"`
	StalenessHrs StalenessHours `json:"staleness_hours"`
	ThresholdHrs StalenessHours `json:"threshold_hours"`
	GapHrs       StalenessHours `json:"gap_hours"`
	Stale        bool           `json:"stale"`
	Message      string         `json:"message"`
}

// IsStale reports whether the staleness check detected stale observations.
func (r *Result) IsStale() bool {
	return r != nil && r.Stale
}

// IsFresh reports whether the observations are within the freshness threshold.
func (r *Result) IsFresh() bool {
	return r != nil && !r.Stale
}

// HasGap reports whether the staleness gap exceeds zero.
func (r *Result) HasGap() bool {
	return r != nil && r.GapHrs > 0
}

// HasSnapshot reports whether a valid non-zero snapshot capture timestamp was found.
func (r *Result) HasSnapshot() bool {
	return r != nil && !r.MostRecent.IsZero()
}

// GapHours returns the staleness gap in hours (0 if not stale or nil).
func (r *Result) GapHours() StalenessHours {
	if r == nil {
		return 0
	}
	return r.GapHrs
}

// AgeHours returns the observation staleness age in hours (0 if nil).
func (r *Result) AgeHours() StalenessHours {
	if r == nil {
		return 0
	}
	return r.StalenessHrs
}

// ThresholdHours returns the configured freshness threshold in hours (0 if nil).
func (r *Result) ThresholdHours() StalenessHours {
	if r == nil {
		return 0
	}
	return r.ThresholdHrs
}

// AgeDays returns the observation staleness age in days (0.0 if nil).
func (r *Result) AgeDays() float64 {
	if r == nil {
		return 0
	}
	return r.StalenessHrs.Days()
}

// Status returns a human-readable status description: "stale", "fresh", or "unknown".
func (r *Result) Status() string {
	if r == nil {
		return "unknown"
	}
	if r.Stale {
		return "stale"
	}
	return "fresh"
}

// Check compares the most recent snapshot against the threshold.
func Check(snapshots asset.Snapshots, threshold time.Duration, now time.Time) *Result {
	if len(snapshots) == 0 {
		return &Result{
			Threshold:    threshold,
			ThresholdHrs: StalenessHours(threshold.Hours()),
			Stale:        true,
			Message:      "no snapshots found",
		}
	}

	mostRecent := snapshots[0].CapturedAt
	for _, snap := range snapshots[1:] {
		if snap.CapturedAt.After(mostRecent) {
			mostRecent = snap.CapturedAt
		}
	}

	if mostRecent.IsZero() {
		return &Result{
			Threshold:    threshold,
			ThresholdHrs: StalenessHours(threshold.Hours()),
			Stale:        true,
			Message:      "snapshot capture timestamp missing or zero",
		}
	}

	age := now.Sub(mostRecent)
	stale := age > threshold

	r := &Result{
		MostRecent:   mostRecent,
		Staleness:    age,
		Threshold:    threshold,
		StalenessHrs: StalenessHours(age.Hours()),
		ThresholdHrs: StalenessHours(threshold.Hours()),
		Stale:        stale,
	}

	if stale {
		gap := age - threshold
		r.Gap = gap
		r.GapHrs = StalenessHours(gap.Hours())
		r.Message = fmt.Sprintf("observation staleness threshold exceeded: most recent snapshot %s (%.0f hours ago), threshold %.0fh",
			mostRecent.Format(time.RFC3339), age.Hours(), threshold.Hours())
	}

	return r
}
