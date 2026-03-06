package kernel

import "time"

// TimeWindow represents a half-open time interval [Start, End).
// Use Contains to check if a point falls within the window, and
// Overlaps to check if two windows intersect.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// Contains reports whether t falls within the half-open interval [Start, End).
func (w TimeWindow) Contains(t time.Time) bool {
	return !t.Before(w.Start) && t.Before(w.End)
}

// ContainsExclusive reports whether t falls within the open interval (Start, End).
func (w TimeWindow) ContainsExclusive(t time.Time) bool {
	return t.After(w.Start) && t.Before(w.End)
}

// Overlaps reports whether two windows share any points in common.
func (w TimeWindow) Overlaps(other TimeWindow) bool {
	return w.Start.Before(other.End) && other.Start.Before(w.End)
}

// Span returns the duration of the window.
func (w TimeWindow) Span() time.Duration {
	return w.End.Sub(w.Start)
}
