package policy

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

const (
	paramRecurrenceLimit = "recurrence_limit"
	paramWindowDays      = "window_days"
)

// RecurrencePolicy defines the thresholds for frequency-based security violations.
// Example: "Flag if an asset becomes unsafe 3 times within a 7-day window."
type RecurrencePolicy struct {
	Limit      int
	WindowDays int
}

// ParseRecurrencePolicy extracts recurrence settings from the raw control parameters.
func ParseRecurrencePolicy(params ControlParams) RecurrencePolicy {
	return RecurrencePolicy{
		Limit:      params.paramInt(paramRecurrenceLimit),
		WindowDays: params.paramInt(paramWindowDays),
	}
}

// Configured reports whether the policy has valid parameters to perform an evaluation.
func (p RecurrencePolicy) Configured() bool {
	return p.Limit > 0 && p.WindowDays > 0
}

// WindowDuration converts the day-based window into a standard time.Duration.
func (p RecurrencePolicy) WindowDuration() time.Duration {
	return time.Duration(p.WindowDays) * 24 * time.Hour
}

// Window returns a TimeWindow representing the evaluation period ending at the provided time.
func (p RecurrencePolicy) Window(now time.Time) kernel.TimeWindow {
	// AddDate handles calendar complexities better than duration math for day units.
	start := now.AddDate(0, 0, -p.WindowDays)
	return kernel.NewTimeWindow(start, now)
}
