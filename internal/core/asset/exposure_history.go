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

// RecurringViolationCount returns count of windows that started in the time range.
func (h ExposureHistory) RecurringViolationCount(w kernel.TimeWindow) int {
	var count int
	for _, window := range h.windows {
		start := window.OpenedAt()
		if !start.After(w.Start) {
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
