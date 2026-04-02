package asset

import (
	"fmt"
	"math"
	"time"
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
// Returns an error if the asset ID is empty (e.g. from malformed observation data).
func NewTimeline(a Asset) (*Timeline, error) {
	if a.ID.IsEmpty() {
		return nil, fmt.Errorf("asset ID must not be empty")
	}
	return &Timeline{
		ID:    a.ID,
		asset: a,
	}, nil
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
func (rt *Timeline) Stats() ObservationStats {
	return rt.stats
}

// History returns archived unsafe episodes for this timeline.
func (rt *Timeline) History() EpisodeHistory {
	return rt.history
}

// RecordObservation updates continuity metrics and applies the unsafe/safe transition.
// Returns an error if the timestamp is zero (e.g. from malformed observation data).
func (rt *Timeline) RecordObservation(t time.Time, isUnsafe bool) error {
	if t.IsZero() {
		return fmt.Errorf("record observation: time must not be zero")
	}

	if err := rt.stats.RecordObservation(t); err != nil {
		return err
	}
	if isUnsafe {
		rt.handleUnsafe(t)
	} else {
		rt.handleSafe(t)
	}
	rt.checkContracts()
	return nil
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
// Returns an error if 'now' is before the episode start time.
func (rt *Timeline) UnsafeDuration(now time.Time) (time.Duration, error) {
	if !rt.HasOpenEpisode() {
		return 0, nil
	}
	if !now.IsZero() && now.Before(rt.activeEpisode.StartAt()) {
		return 0, fmt.Errorf("unsafe duration: 'now' (%s) must not be before episode start (%s)", now.Format(time.RFC3339), rt.activeEpisode.StartAt().Format(time.RFC3339))
	}
	return now.Sub(rt.activeEpisode.StartAt()), nil
}

// checkContracts panics on invariant violations that indicate a programming error.
// NewTimeline validates the ID at construction; this guard catches corruption
// from unsafe internal mutations, not from external data.
func (rt *Timeline) checkContracts() {
	if rt.ID.IsEmpty() {
		panic("contract violated: Timeline.ID must be non-empty")
	}
}

// ExceedsUnsafeThreshold reports whether the current unsafe duration exceeds
// the given threshold. Returns false when there is no open episode.
func (rt *Timeline) ExceedsUnsafeThreshold(now time.Time, maxUnsafe time.Duration) (bool, error) {
	d, err := rt.UnsafeDuration(now)
	if err != nil {
		return false, err
	}
	return d > maxUnsafe, nil
}

// FormatUnsafeSummary builds a user-facing explanation for the current unsafe state.
func (rt *Timeline) FormatUnsafeSummary(threshold time.Duration, now time.Time) string {
	if !rt.HasOpenEpisode() {
		return "Asset is currently in an unsafe state."
	}

	d, _ := rt.UnsafeDuration(now)
	return fmt.Sprintf(
		"Asset has been unsafe for %d hours (threshold: %d hours). Unsafe since %s.",
		int(math.Round(d.Hours())),
		int(math.Round(threshold.Hours())),
		rt.FirstUnsafeAt().Format(time.RFC3339),
	)
}
