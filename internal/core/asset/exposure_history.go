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

// WindowSummary returns count and bounds for windows started in the time range.
func (h ExposureHistory) WindowSummary(w kernel.TimeWindow) (count int, first, last time.Time) {
	for _, window := range h.windows {
		start := window.OpenedAt()
		if !start.After(w.Start) {
			continue
		}
		if !start.Before(w.End) {
			break
		}

		count++
		if first.IsZero() {
			first = start
		}
		if endAt := window.ResolvedAt(); last.IsZero() || endAt.After(last) {
			last = endAt
		}
	}
	return count, first, last
}
