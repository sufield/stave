// Package staleness detects observation collection gaps by comparing
// the most recent snapshot timestamp against a freshness threshold.
// Produces a COLLECTION_STALENESS finding when data is too old.
package staleness

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// Result holds the staleness check outcome.
type Result struct {
	MostRecent   time.Time `json:"most_recent_snapshot"`
	StalenessHrs float64   `json:"staleness_hours"`
	ThresholdHrs float64   `json:"threshold_hours"`
	GapHrs       float64   `json:"gap_hours"`
	Stale        bool      `json:"stale"`
	Message      string    `json:"message"`
}

// Check compares the most recent snapshot against the threshold.
func Check(snapshots []asset.Snapshot, threshold time.Duration, now time.Time) *Result {
	if len(snapshots) == 0 {
		return &Result{
			ThresholdHrs: threshold.Hours(),
			Stale:        true,
			Message:      "no snapshots found",
		}
	}

	mostRecent := snapshots[0].CapturedAt
	for i := 1; i < len(snapshots); i++ {
		if snapshots[i].CapturedAt.After(mostRecent) {
			mostRecent = snapshots[i].CapturedAt
		}
	}

	if mostRecent.IsZero() {
		return &Result{
			ThresholdHrs: threshold.Hours(),
			Stale:        true,
			Message:      "snapshot capture timestamp missing or zero",
		}
	}

	age := now.Sub(mostRecent)
	stale := age > threshold

	r := &Result{
		MostRecent:   mostRecent,
		StalenessHrs: age.Hours(),
		ThresholdHrs: threshold.Hours(),
		Stale:        stale,
	}

	if stale {
		r.GapHrs = (age - threshold).Hours()
		r.Message = fmt.Sprintf("observation staleness threshold exceeded: most recent snapshot %s (%.0f hours ago), threshold %.0fh",
			mostRecent.Format(time.RFC3339), age.Hours(), threshold.Hours())
	}

	return r
}
