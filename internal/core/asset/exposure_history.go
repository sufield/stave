package asset

import (
	"slices"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// ExposureHistory stores resolved exposure windows.
// CONTRACT: only resolved windows are archived.
type ExposureHistory struct {
	windows []ExposureWindow
}

// Record archives a resolved window in chronological order by OpenedAt.
// PRECONDITION: active windows are ignored.
func (h *ExposureHistory) Record(w ExposureWindow) {
	if w.IsActive() {
		return
	}
	i, _ := slices.BinarySearchFunc(h.windows, w, func(a, b ExposureWindow) int {
		return a.openedAt.Compare(b.openedAt)
	})
	h.windows = slices.Insert(h.windows, i, w)
}

// Count returns number of archived exposure windows.
func (h ExposureHistory) Count() int {
	return len(h.windows)
}

// Windows returns a chronologically-ordered copy of the archived
// exposure windows. The clone is intentional — the history's
// invariant (windows sorted by openedAt, only resolved windows
// archived) is enforced inside Record; callers receiving the slice
// must not mutate the live backing array. Used by the SIR builder
// to surface per-control dwell history without breaking the
// no-mutation contract that the lifecycle pipeline relies on.
func (h ExposureHistory) Windows() []ExposureWindow {
	if len(h.windows) == 0 {
		return nil
	}
	out := make([]ExposureWindow, len(h.windows))
	copy(out, h.windows)
	return out
}

// RecurringViolationCount returns the count of windows whose start falls
// inside the half-open range [w.Start, w.End). The lower bound is
// inclusive — a window opened exactly at w.Start is counted — to match
// WindowSummary's overlap semantics.
func (h ExposureHistory) RecurringViolationCount(w kernel.TimeWindow) int {
	var count int
	for _, window := range h.windows {
		start := window.OpenedAt()
		if start.Before(w.Start) {
			continue
		}
		if !start.Before(w.End) {
			break
		}
		count++
	}
	return count
}

// WindowSummary returns count and bounds for windows that overlap the time range.
// A window overlaps if it started before the period ended AND it ended after
// the period started (or is still open). This correctly counts windows that
// started before the analysis period but were still active during it.
func (h ExposureHistory) WindowSummary(w kernel.TimeWindow) (count int, first, last time.Time) {
	for _, window := range h.windows {
		start := window.OpenedAt()

		// Window must have started before the period ends.
		if !start.Before(w.End) {
			break // windows are sorted — no further matches
		}

		// Window must still be active at or after the period start.
		end := window.ResolvedAt()
		if !end.IsZero() && !end.After(w.Start) {
			continue // window ended before period started
		}

		count++
		if first.IsZero() || start.Before(first) {
			first = start
		}
		if end.IsZero() {
			// Still-open window — use period end as the effective last time.
			if last.IsZero() || w.End.After(last) {
				last = w.End
			}
		} else if last.IsZero() || end.After(last) {
			last = end
		}
	}
	return count, first, last
}
