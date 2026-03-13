package ports

import "time"

// Clock provides an abstraction for the system clock,
// allowing for deterministic time in tests.
type Clock interface {
	Now() time.Time
}

// RealClock implements Clock using the standard time package.
type RealClock struct{}

// NewRealClock returns a Clock backed by the system wall clock.
func NewRealClock() Clock {
	return RealClock{}
}

// Now returns the current time in UTC.
func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

// FixedClock provides a static time value for testing purposes.
type FixedClock time.Time

// Now returns the underlying fixed time.
func (f FixedClock) Now() time.Time {
	return time.Time(f)
}
