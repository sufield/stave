package cmdutil

import (
	"fmt"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// ParseDurationFlag parses a duration flag value and wraps errors with the flag name.
func ParseDurationFlag(val, flag string) (time.Duration, error) {
	d, err := kernel.ParseDuration(val)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q (use format: 168h, 7d, or 1d12h)", flag, val)
	}
	return d, nil
}

// ParseRFC3339 parses an RFC3339 timestamp with a flag-name error message.
func ParseRFC3339(raw, flag string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s %q (use RFC3339: 2026-01-15T00:00:00Z)", flag, raw)
	}
	return t.UTC(), nil
}
