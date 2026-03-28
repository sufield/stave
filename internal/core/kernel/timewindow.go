package kernel

import (
	"fmt"
	"time"
)

// TimeWindow represents a half-open time interval [Start, End).
// It is the idiomatic way to represent a span of time in Go.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// NewTimeWindow creates a new window. If end is before start,
// they are swapped to ensure a valid positive interval.
func NewTimeWindow(start, end time.Time) TimeWindow {
	if end.Before(start) {
		return TimeWindow{Start: end, End: start}
	}
	return TimeWindow{Start: start, End: end}
}

// IsValid reports whether the window is correctly ordered (Start <= End)
// and neither time is the zero value.
func (w TimeWindow) IsValid() bool {
	return !w.Start.IsZero() && !w.End.IsZero() && !w.End.Before(w.Start)
}

// Contains reports whether t falls within the half-open interval [Start, End).
func (w TimeWindow) Contains(t time.Time) bool {
	return (t.Equal(w.Start) || t.After(w.Start)) && t.Before(w.End)
}

// Overlaps reports whether two windows share any common time points.
func (w TimeWindow) Overlaps(other TimeWindow) bool {
	if !w.IsValid() || !other.IsValid() {
		return false
	}
	return w.Start.Before(other.End) && other.Start.Before(w.End)
}

// Duration returns the length of time between Start and End.
func (w TimeWindow) Duration() time.Duration {
	if w.End.Before(w.Start) {
		return 0
	}
	return w.End.Sub(w.Start)
}

// String returns a human-readable representation of the window.
func (w TimeWindow) String() string {
	if !w.IsValid() {
		return "[invalid window]"
	}
	return fmt.Sprintf("[%s, %s)", w.Start.Format(time.RFC3339), w.End.Format(time.RFC3339))
}

// IsZero reports whether the window has no time set.
func (w TimeWindow) IsZero() bool {
	return w.Start.IsZero() && w.End.IsZero()
}
