package policy

import (
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// RecurrencePolicy holds the parsed recurrence parameters for an control.
// Parsed once from ControlParams to avoid repeated untyped map lookups.
type RecurrencePolicy struct {
	Limit      int
	WindowDays int
}

// ParseRecurrencePolicy extracts recurrence parameters from control params.
func ParseRecurrencePolicy(params ControlParams) RecurrencePolicy {
	return RecurrencePolicy{
		Limit:      params.Int("recurrence_limit"),
		WindowDays: params.Int("window_days"),
	}
}

// Configured reports whether both recurrence parameters are defined and valid.
func (rp RecurrencePolicy) Configured() bool {
	return rp.Limit > 0 && rp.WindowDays > 0
}

// WindowDuration returns the recurrence window as a time.Duration.
func (rp RecurrencePolicy) WindowDuration() time.Duration {
	return time.Duration(rp.WindowDays) * 24 * time.Hour
}

// WindowStart returns the start of the recurrence window relative to now.
func (rp RecurrencePolicy) WindowStart(now time.Time) time.Time {
	return now.AddDate(0, 0, -rp.WindowDays)
}

// Window returns the recurrence time window ending at now.
func (rp RecurrencePolicy) Window(now time.Time) kernel.TimeWindow {
	return kernel.TimeWindow{Start: rp.WindowStart(now), End: now}
}
