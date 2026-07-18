package asset

import "testing"

func TestCheckContracts_PanicsOnNegativeCount(t *testing.T) {
	t.Parallel()
	s := &ObservationStats{}
	s.observationCount = -1

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for negative observationCount")
		}
		msg, ok := r.(string)
		if !ok || msg != "contract violated: ObservationStats.observationCount must be >= 0" {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	s.checkContracts()
}

func TestCheckContracts_PanicsOnInvertedTimestamps(t *testing.T) {
	t.Parallel()
	s := &ObservationStats{}
	s.observationCount = 2
	s.firstSeenAt = s.lastSeenAt.Add(1) // firstSeen after lastSeen

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for inverted timestamps")
		}
		msg, ok := r.(string)
		if !ok || msg != "contract violated: ObservationStats.firstSeenAt must be <= lastSeenAt when count > 0" {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	s.checkContracts()
}
