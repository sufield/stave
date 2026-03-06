package asset

import "time"

// ObservationStats tracks continuity metrics for resource observations.
// It is agnostic to whether a resource is safe or unsafe.
// CONTRACT: coverageSpan is always derived from (lastSeenAt - firstSeenAt).
type ObservationStats struct {
	firstSeenAt      time.Time
	lastSeenAt       time.Time
	coverageSpan     time.Duration
	observationCount int
	maxGap           time.Duration
	prevSeenAt       time.Time
}

// HasFirstObservation reports whether at least one observation was recorded.
func (s *ObservationStats) HasFirstObservation() bool {
	return !s.firstSeenAt.IsZero()
}

// HasCoverageData reports whether both first and last timestamps are available.
func (s *ObservationStats) HasCoverageData() bool {
	return !s.firstSeenAt.IsZero() && !s.lastSeenAt.IsZero()
}

// FirstSeenAt returns the first observation timestamp.
func (s *ObservationStats) FirstSeenAt() time.Time {
	return s.firstSeenAt
}

// LastSeenAt returns the last observation timestamp.
func (s *ObservationStats) LastSeenAt() time.Time {
	return s.lastSeenAt
}

// CoverageSpan returns duration between first and last observation.
func (s *ObservationStats) CoverageSpan() time.Duration {
	return s.coverageSpan
}

// ObservationCount returns number of recorded observations.
func (s *ObservationStats) ObservationCount() int {
	return s.observationCount
}

// MaxGap returns the maximum interval between consecutive observations.
func (s *ObservationStats) MaxGap() time.Duration {
	return s.maxGap
}

// RecordObservation updates continuity metrics with a new observation time.
// CONTRACT: out-of-order timestamps are ignored.
func (s *ObservationStats) RecordObservation(t time.Time) {
	if t.IsZero() {
		panic("precondition failed: RecordObservation requires non-zero time")
	}

	if s.observationCount == 0 {
		s.firstSeenAt, s.lastSeenAt, s.prevSeenAt = t, t, t
		s.observationCount = 1
		return
	}
	if t.Before(s.prevSeenAt) {
		return
	}
	if gap := t.Sub(s.prevSeenAt); gap > s.maxGap {
		s.maxGap = gap
	}

	s.lastSeenAt = t
	s.observationCount++
	s.coverageSpan = s.lastSeenAt.Sub(s.firstSeenAt)
	s.prevSeenAt = t

	s.checkContracts()
}

func (s *ObservationStats) checkContracts() {
	if s.observationCount < 0 {
		panic("contract violated: ObservationStats.observationCount must be >= 0")
	}
	if s.observationCount > 0 && s.firstSeenAt.After(s.lastSeenAt) {
		panic("contract violated: ObservationStats.firstSeenAt must be <= lastSeenAt when count > 0")
	}
}
