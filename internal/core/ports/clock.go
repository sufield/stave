package ports

import "time"

// Clock provides an abstraction for the system clock,
// allowing for deterministic time in tests.
//
// IsUserProvided distinguishes user-supplied clocks (--now,
// FixedClock) from the system wall-clock. The assessor branches on
// this to honour `--now` overrides as the audit timestamp instead of
// reaching for the latest snapshot's CapturedAt; the previous shape
// type-asserted to ports.FixedClock at the call site, which broke
// when callers wrapped the clock in their own type that still
// represented an explicit user choice. Putting the question on the
// interface lets every implementation answer for itself.
type Clock interface {
	Now() time.Time
	IsUserProvided() bool
}

// RealClock implements Clock using the standard time package.
// Use RealClock{} directly — no constructor needed for a zero-value type.
type RealClock struct{}

// Now returns the current time in UTC.
func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

// IsUserProvided returns false: the system wall-clock is not a user
// override.
func (RealClock) IsUserProvided() bool { return false }

// FixedClock provides a static time value for testing purposes.
type FixedClock time.Time

// Now returns the underlying fixed time.
func (f FixedClock) Now() time.Time {
	return time.Time(f)
}

// IsUserProvided returns true: a FixedClock represents an explicit
// caller-supplied time (--now or test-fixture clock).
func (FixedClock) IsUserProvided() bool { return true }
