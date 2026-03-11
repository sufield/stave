package asset

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// Episode represents a contiguous period where an asset remained unsafe.
// An episode starts when an asset transitions from safe to unsafe and ends
// when it transitions back to safe. Episodes are used for recurrence detection.
// CONTRACT: for closed episodes, endAt is never before startAt.
type Episode struct {
	startAt time.Time
	endAt   time.Time
	open    bool
}

// StartAt returns the episode start timestamp.
func (e Episode) StartAt() time.Time {
	return e.startAt
}

// EndAt returns the episode end timestamp.
// Open episodes return the zero value.
func (e Episode) EndAt() time.Time {
	return e.endAt
}

// IsOpen returns true when this episode is still ongoing.
func (e Episode) IsOpen() bool {
	return e.open
}

// EffectiveEndAt returns the episode end timestamp; for open episodes it returns now.
func (e Episode) EffectiveEndAt(now time.Time) time.Time {
	if e.IsOpen() {
		return now
	}
	return e.endAt
}

// Close transitions an open episode to a closed episode.
// The operation is idempotent for already-closed episodes.
func (e Episode) Close(endAt time.Time) Episode {
	if !e.IsOpen() {
		return e
	}

	effectiveEnd := endAt
	if effectiveEnd.Before(e.startAt) {
		effectiveEnd = e.startAt
	}

	return Episode{
		startAt: e.startAt,
		endAt:   effectiveEnd,
		open:    false,
	}
}

// NewClosedEpisode creates a completed episode enforcing StartAt <= EndAt.
func NewClosedEpisode(start, end time.Time) (Episode, error) {
	ep, err := NewOpenEpisode(start)
	if err != nil {
		return Episode{}, err
	}
	return ep.Close(end), nil
}

// NewOpenEpisode creates an ongoing episode with no end time.
func NewOpenEpisode(start time.Time) (Episode, error) {
	if start.IsZero() {
		return Episode{}, fmt.Errorf("episode: start_at is required")
	}
	return Episode{startAt: start, open: true}, nil
}

// OverlapsWindow reports whether the episode overlaps the given time window.
func (e Episode) OverlapsWindow(w kernel.TimeWindow) bool {
	return e.EffectiveEndAt(w.End).After(w.Start) && e.StartAt().Before(w.End)
}

type episodeJSON struct {
	StartAt time.Time `json:"start_at"`
	EndAt   time.Time `json:"end_at"`
	Open    bool      `json:"open"`
}

// MarshalJSON serializes Episode while keeping fields private.
func (e Episode) MarshalJSON() ([]byte, error) {
	return json.Marshal(episodeJSON{
		StartAt: e.startAt,
		EndAt:   e.endAt,
		Open:    e.open,
	})
}

// UnmarshalJSON deserializes Episode while enforcing episode controls.
func (e *Episode) UnmarshalJSON(data []byte) error {
	var payload episodeJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	if payload.StartAt.IsZero() {
		return fmt.Errorf("episode start_at is required")
	}

	if payload.Open {
		ep, err := NewOpenEpisode(payload.StartAt)
		if err != nil {
			return err
		}
		*e = ep
		return nil
	}

	ep, err := NewClosedEpisode(payload.StartAt, payload.EndAt)
	if err != nil {
		return err
	}
	*e = ep
	return nil
}
