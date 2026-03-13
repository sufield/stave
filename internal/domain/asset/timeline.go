package asset

import (
	"fmt"
	"math"
	"time"

	"github.com/sufield/stave/internal/dbc"
)

// Timeline tracks the unsafe-state episodes of an asset across snapshots.
// It records when the asset first became unsafe, when it was last seen unsafe,
// and maintains a history of completed episodes for recurrence detection.
//
// Note: "Timeline" refers to unsafe-state episode tracking, not S3 resource
// lifecycle configuration (which lives in storage.LifecycleConfig).
//
// CONTRACT: historical episodes are archived as closed entries in history.
type Timeline struct {
	ID    ID
	asset Asset

	activeEpisode    *Episode
	lastSeenUnsafeAt time.Time

	history EpisodeHistory
	stats   ObservationStats
}

// NewTimeline constructs an empty timeline for an asset.
func NewTimeline(a Asset) *Timeline {
	if a.ID.IsEmpty() {
		panic("precondition failed: NewTimeline requires non-empty asset ID")
	}
	return &Timeline{
		ID:    a.ID,
		asset: a,
	}
}

// Asset returns the latest observed asset state for this timeline.
func (rt *Timeline) Asset() Asset {
	return rt.asset
}

// SetAsset updates the latest observed asset state for this timeline.
func (rt *Timeline) SetAsset(a Asset) {
	if rt.ID.IsEmpty() {
		rt.ID = a.ID
	}
	rt.asset = a
	rt.checkContracts()
}

// Stats returns continuity metrics for this timeline.
func (rt *Timeline) Stats() *ObservationStats {
	return &rt.stats
}

// History returns archived unsafe episodes for this timeline.
func (rt *Timeline) History() *EpisodeHistory {
	return &rt.history
}

// RecordObservation updates continuity metrics and applies the unsafe/safe transition.
func (rt *Timeline) RecordObservation(t time.Time, isUnsafe bool) {
	if t.IsZero() {
		panic("precondition failed: Timeline.RecordObservation requires non-zero time")
	}

	rt.stats.RecordObservation(t)
	if isUnsafe {
		rt.handleUnsafe(t)
	} else {
		rt.handleSafe(t)
	}
	rt.checkContracts()
}

// CurrentlySafe reports whether the asset is in a safe state.
func (rt *Timeline) CurrentlySafe() bool {
	return rt.activeEpisode == nil
}

// CurrentlyUnsafe reports whether the asset is in an unsafe state.
func (rt *Timeline) CurrentlyUnsafe() bool {
	return rt.activeEpisode != nil
}

// FirstUnsafeAt returns the start of the current unsafe streak.
func (rt *Timeline) FirstUnsafeAt() time.Time {
	if rt.activeEpisode == nil {
		return time.Time{}
	}
	return rt.activeEpisode.StartAt()
}

// LastSeenUnsafeAt returns the most recent timestamp where the asset was observed unsafe.
func (rt *Timeline) LastSeenUnsafeAt() time.Time {
	return rt.lastSeenUnsafeAt
}

// HasUnsafeTimestamps reports whether both FirstUnsafeAt and LastSeenUnsafe are set.
func (rt *Timeline) HasUnsafeTimestamps() bool {
	return !rt.FirstUnsafeAt().IsZero() && !rt.lastSeenUnsafeAt.IsZero()
}

// MissingUnsafeTimestamps reports whether either FirstUnsafeAt or LastSeenUnsafe is unset.
func (rt *Timeline) MissingUnsafeTimestamps() bool {
	return !rt.HasUnsafeTimestamps()
}

func (rt *Timeline) handleUnsafe(t time.Time) {
	if rt.activeEpisode == nil {
		episode, _ := NewOpenEpisode(t)
		rt.activeEpisode = &episode
	}
	if t.After(rt.lastSeenUnsafeAt) || rt.lastSeenUnsafeAt.IsZero() {
		rt.lastSeenUnsafeAt = t
	}
}

func (rt *Timeline) handleSafe(at time.Time) {
	if rt.activeEpisode == nil {
		return
	}

	closed := rt.activeEpisode.Close(rt.closeTimestamp(at))
	rt.history.Record(closed)
	rt.activeEpisode = nil
	rt.resetUnsafeState()
	dbc.ExpensiveCheck(rt.verifyHistoryOrdering)
}

func (rt *Timeline) closeTimestamp(at time.Time) time.Time {
	if !rt.lastSeenUnsafeAt.IsZero() {
		return rt.lastSeenUnsafeAt
	}
	if !at.IsZero() {
		return at
	}
	if rt.activeEpisode != nil {
		return rt.activeEpisode.StartAt()
	}
	return time.Time{}
}

func (rt *Timeline) resetUnsafeState() {
	rt.lastSeenUnsafeAt = time.Time{}
}

// HasOpenEpisode reports whether the asset is currently in an unsafe episode
// with a recorded start time.
func (rt *Timeline) HasOpenEpisode() bool {
	return rt.activeEpisode != nil && rt.activeEpisode.IsOpen()
}

// UnsafeDuration calculates the duration of the current open episode.
// Returns 0 if there is no open episode.
func (rt *Timeline) UnsafeDuration(now time.Time) time.Duration {
	if !rt.HasOpenEpisode() {
		return 0
	}
	if !now.IsZero() && now.Before(rt.activeEpisode.StartAt()) {
		panic("precondition failed: UnsafeDuration 'now' must not be before episode start")
	}
	return now.Sub(rt.activeEpisode.StartAt())
}

func (rt *Timeline) checkContracts() {
	if rt.ID.IsEmpty() {
		panic("contract violated: Timeline.ID must be non-empty")
	}
}

// verifyHistoryOrdering checks that all archived episodes are chronologically ordered.
// O(n) scan — only runs in debug builds via dbc.ExpensiveCheck.
func (rt *Timeline) verifyHistoryOrdering() {
	episodes := rt.history.episodes
	for i := 1; i < len(episodes); i++ {
		if episodes[i].StartAt().Before(episodes[i-1].StartAt()) {
			panic("contract violated: Timeline history episodes are not chronologically ordered")
		}
	}
}

// ExceedsUnsafeThreshold reports whether the current unsafe duration exceeds
// the given threshold. Returns false when there is no open episode.
func (rt *Timeline) ExceedsUnsafeThreshold(now time.Time, maxUnsafe time.Duration) bool {
	return rt.UnsafeDuration(now) > maxUnsafe
}

// FormatUnsafeSummary builds a user-facing explanation for the current unsafe state.
func (rt *Timeline) FormatUnsafeSummary(threshold time.Duration, now time.Time) string {
	if !rt.HasOpenEpisode() {
		return "Asset is currently in an unsafe state."
	}

	return fmt.Sprintf(
		"Asset has been unsafe for %d hours (threshold: %d hours). Unsafe since %s.",
		int(math.Round(rt.UnsafeDuration(now).Hours())),
		int(math.Round(threshold.Hours())),
		rt.FirstUnsafeAt().Format(time.RFC3339),
	)
}
