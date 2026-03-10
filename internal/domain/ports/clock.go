package ports

import "time"

// Clock provides the current time (injectable for testing).
type Clock interface {
	Now() time.Time
}

var (
	_ Clock = RealClock{}
	_ Clock = FixedClock{}
)

// RealClock uses the system clock in UTC.
type RealClock struct{}

// NewRealClock returns the default production clock implementation.
func NewRealClock() RealClock {
	return RealClock{}
}

// Now returns the current wall-clock time in UTC.
func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

// FixedClock returns a fixed point in time for deterministic tests.
type FixedClock struct {
	Time time.Time
}

// Now returns the fixed time.
func (fc FixedClock) Now() time.Time {
	return fc.Time
}
