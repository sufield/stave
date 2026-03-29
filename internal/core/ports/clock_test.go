package ports

import (
	"testing"
	"time"
)

func TestRealClock_Now(t *testing.T) {
	c := RealClock{}
	before := time.Now().UTC()
	got := c.Now()
	after := time.Now().UTC()

	if got.Before(before) || got.After(after) {
		t.Fatalf("RealClock.Now() = %v, not between %v and %v", got, before, after)
	}
	if got.Location() != time.UTC {
		t.Fatalf("RealClock.Now() location = %v, want UTC", got.Location())
	}
}

func TestRealClock_ImplementsClock(t *testing.T) {
	var _ Clock = RealClock{}
}

func TestFixedClock_Now(t *testing.T) {
	ts := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	c := FixedClock(ts)

	got := c.Now()
	if !got.Equal(ts) {
		t.Fatalf("FixedClock.Now() = %v, want %v", got, ts)
	}

	// Multiple calls should return the same time.
	got2 := c.Now()
	if !got2.Equal(ts) {
		t.Fatalf("second call: %v, want %v", got2, ts)
	}
}

func TestFixedClock_ImplementsClock(t *testing.T) {
	var _ Clock = FixedClock(time.Now())
}
