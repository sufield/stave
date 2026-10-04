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

// IsStale reports whether staleness hours exceeds the given threshold hours.
func (sh StalenessHours) IsStale(threshold StalenessHours) bool {
	return sh > threshold
}

// Gap returns the positive staleness gap past threshold hours (0 if not stale).
func (sh StalenessHours) Gap(threshold StalenessHours) StalenessHours {
	if sh <= threshold {
		return 0
	}
	return sh - threshold
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
