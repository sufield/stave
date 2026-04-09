package asset

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/sufield/stave/internal/core/kernel"
)

// ExposureWindow represents a contiguous period where a cloud asset was in a
// non-compliant state. A window opens when a security violation is first detected
// and closes when the asset is remediated. These windows are used to track
// dwell time and detect recurring security regressions.
type ExposureWindow struct {
	openedAt   time.Time
	resolvedAt time.Time
	active     bool
}

// OpenedAt returns the timestamp when the security violation was first detected.
func (w ExposureWindow) OpenedAt() time.Time {
	return w.openedAt
}

// ResolvedAt returns the timestamp when the asset returned to a compliant state.
// Returns a zero value if the window is still active.
func (w ExposureWindow) ResolvedAt() time.Time {
	return w.resolvedAt
}

// IsActive returns true if the asset is currently non-compliant.
func (w ExposureWindow) IsActive() bool {
	return w.active
}

// EffectiveEndAt returns the resolution time; for active windows it returns now.
func (w ExposureWindow) EffectiveEndAt(now time.Time) time.Time {
	if w.IsActive() {
		return now
	}
	return w.resolvedAt
}

// Resolve transitions an active window to a resolved state.
// The operation is idempotent for already-resolved windows.
func (w ExposureWindow) Resolve(resolvedAt time.Time) ExposureWindow {
	if !w.IsActive() {
		return w
	}

	effectiveEnd := resolvedAt
	if effectiveEnd.Before(w.openedAt) {
		effectiveEnd = w.openedAt
	}

	return ExposureWindow{
		openedAt:   w.openedAt,
		resolvedAt: effectiveEnd,
		active:     false,
	}
}

// NewResolvedWindow creates a completed exposure window (OpenedAt <= ResolvedAt).
func NewResolvedWindow(start, end time.Time) ExposureWindow {
	return NewActiveWindow(start).Resolve(end)
}

// NewActiveWindow creates a new ongoing exposure window.
// A zero openedAt is accepted — callers may check OpenedAt().IsZero() if needed.
func NewActiveWindow(openedAt time.Time) ExposureWindow {
	return ExposureWindow{openedAt: openedAt, active: true}
}

// OverlapsWindow reports whether this exposure occurred during the given time window.
func (w ExposureWindow) OverlapsWindow(k kernel.TimeWindow) bool {
	return w.EffectiveEndAt(k.End).After(k.Start) && w.OpenedAt().Before(k.End)
}

type windowJSON struct {
	OpenedAt   time.Time `json:"opened_at"`
	ResolvedAt time.Time `json:"resolved_at"`
	IsActive   bool      `json:"is_active"`
}

// MarshalJSON serializes ExposureWindow while keeping internal fields protected.
func (w ExposureWindow) MarshalJSON() ([]byte, error) {
	return json.Marshal(windowJSON{
		OpenedAt:   w.openedAt,
		ResolvedAt: w.resolvedAt,
		IsActive:   w.active,
	})
}

// UnmarshalJSON deserializes ExposureWindow while enforcing resolution logic.
func (w *ExposureWindow) UnmarshalJSON(data []byte) error {
	var payload windowJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}
	if payload.OpenedAt.IsZero() {
		return errors.New("exposure_window opened_at is required")
	}

	if payload.IsActive {
		*w = NewActiveWindow(payload.OpenedAt)
		return nil
	}

	*w = NewResolvedWindow(payload.OpenedAt, payload.ResolvedAt)
	return nil
}
