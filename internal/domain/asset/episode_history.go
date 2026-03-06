package asset

import (
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// EpisodeHistory stores completed unsafe episodes.
// CONTRACT: only closed episodes are archived.
type EpisodeHistory struct {
	episodes []Episode
}

// Record archives a closed episode.
// PRECONDITION: open episodes are ignored.
func (h *EpisodeHistory) Record(e Episode) {
	if e.IsOpen() {
		return
	}
	h.episodes = append(h.episodes, e)

	if last := h.episodes[len(h.episodes)-1]; last.IsOpen() {
		panic("contract violated: EpisodeHistory must only contain closed episodes")
	}
}

// Count returns number of archived episodes.
func (h *EpisodeHistory) Count() int {
	return len(h.episodes)
}

// RecurringViolationCount returns count of episodes that started in the window.
func (h *EpisodeHistory) RecurringViolationCount(w kernel.TimeWindow) int {
	var count int
	for _, episode := range h.episodes {
		if w.ContainsExclusive(episode.StartAt()) {
			count++
		}
	}
	return count
}

// WindowSummary returns count and bounds for episodes started in the window.
func (h *EpisodeHistory) WindowSummary(w kernel.TimeWindow) (count int, first, last time.Time) {
	for _, episode := range h.episodes {
		if !w.ContainsExclusive(episode.StartAt()) {
			continue
		}

		count++
		startAt := episode.StartAt()
		if first.IsZero() || startAt.Before(first) {
			first = startAt
		}

		endAt := episode.EndAt()
		if last.IsZero() || endAt.After(last) {
			last = endAt
		}
	}
	return count, first, last
}
