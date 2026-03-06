package timeutil

import (
	"fmt"
	"time"

	"github.com/sufield/stave/internal/domain/kernel"
)

// FormatDuration formats a duration for CLI flags and evidence strings.
// Delegates to kernel.FormatDuration; domain code should import kernel directly.
func FormatDuration(d time.Duration) string {
	return kernel.FormatDuration(d)
}

// FormatDurationHuman formats a duration for human display.
// Delegates to kernel.FormatDurationHuman; domain code should import kernel directly.
func FormatDurationHuman(d time.Duration) string {
	return kernel.FormatDurationHuman(d)
}

// ParseDuration parses a duration string that supports days (e.g., "7d", "168h", "1d12h").
// Delegates to kernel.ParseDuration; domain code should import kernel directly.
func ParseDuration(s string) (time.Duration, error) {
	return kernel.ParseDuration(s)
}

// ParseDurationFlag parses a duration flag value and wraps parse errors with
// a user-facing message that includes the flag name and accepted formats.
func ParseDurationFlag(val, flag string) (time.Duration, error) {
	d, err := kernel.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q (use format: 168h, 7d, or 1d12h)", flag, val)
	}
	return d, nil
}
