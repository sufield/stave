package controldef

import (
	"time"

	"github.com/sufield/stave/internal/core/kernel"
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

// Enabled reports whether the policy has valid parameters to perform an evaluation.
func (p RecurrencePolicy) Enabled() bool {
	return p.Limit > 0 && p.WindowDays > 0
}

// WindowDuration converts the day-based window into a standard time.Duration.
// This assumes 24-hour days; for calendar-accurate lookups across DST
// boundaries, use Window() instead.
func (p RecurrencePolicy) WindowDuration() time.Duration {
	return time.Duration(p.WindowDays) * 24 * time.Hour
}

// Window returns a TimeWindow representing the evaluation period ending at the provided time.
// Returns a zero TimeWindow if the policy is not enabled.
func (p RecurrencePolicy) Window(now time.Time) kernel.TimeWindow {
	if !p.Enabled() {
		return kernel.TimeWindow{}
	}
	// AddDate handles calendar complexities better than duration math for day units.
	start := now.AddDate(0, 0, -p.WindowDays)
	return kernel.NewTimeWindow(start, now)
}
