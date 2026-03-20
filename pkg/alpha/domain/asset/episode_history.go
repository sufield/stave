package asset

import (
	"slices"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// EpisodeHistory stores completed unsafe episodes.
// CONTRACT: only closed episodes are archived.
type EpisodeHistory struct {
	episodes []Episode
}

// Record archives a closed episode in chronological order by StartAt.
// PRECONDITION: open episodes are ignored.
func (h *EpisodeHistory) Record(e Episode) {
	if e.IsOpen() {
		return
	}
	// Insert in sorted position so scans can short-circuit by time.
	i, _ := slices.BinarySearchFunc(h.episodes, e, func(a, b Episode) int {
		return a.startAt.Compare(b.startAt)
	})
	h.episodes = slices.Insert(h.episodes, i, e)
}

// Count returns number of archived episodes.
func (h *EpisodeHistory) Count() int {
	return len(h.episodes)
}

// RecurringViolationCount returns count of episodes that started in the window.
// Episodes are sorted by StartAt, so we skip before the window and break after.
func (h *EpisodeHistory) RecurringViolationCount(w kernel.TimeWindow) int {
	var count int
	for _, episode := range h.episodes {
		start := episode.StartAt()
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

// WindowSummary returns count and bounds for episodes started in the window.
// Episodes are sorted by StartAt, so first is taken from the earliest match
// and we break once past the window.
func (h *EpisodeHistory) WindowSummary(w kernel.TimeWindow) (count int, first, last time.Time) {
	for _, episode := range h.episodes {
		start := episode.StartAt()
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
		if endAt := episode.EndAt(); last.IsZero() || endAt.After(last) {
			last = endAt
		}
	}
	return count, first, last
}
