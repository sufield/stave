package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Duration is a time.Duration that marshals to/from a human-readable string
// (e.g. "168h", "7d") in JSON and YAML, instead of raw nanoseconds.
type Duration time.Duration

// Std converts back to a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d Duration) String() string { return FormatDuration(time.Duration(d)) }

// MarshalJSON writes the duration as a human-readable string.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON reads a human-readable duration string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	parsed, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

const hoursPerDay = 24

var dayTokenPattern = regexp.MustCompile(`(?i)(\d+(?:\.\d+)?)d`)

// FormatDuration formats a duration for CLI flags and evidence strings.
// Uses days when evenly divisible by 24 hours, otherwise hours.
func FormatDuration(d time.Duration) string {
	hours := int64(d.Hours())
	if hours == 0 {
		return "0h"
	}
	if hours%hoursPerDay == 0 {
		return fmt.Sprintf("%dd", hours/hoursPerDay)
	}
	return fmt.Sprintf("%dh", hours)
}

// FormatDurationHuman formats a duration for human display.
// Shows compound form like "2d6h" when there are remaining hours.
func FormatDurationHuman(d time.Duration) string {
	if d == 0 {
		return "0h"
	}
	hours := int64(d.Hours())
	days := hours / hoursPerDay
	remainingHours := hours % hoursPerDay

	switch {
	case days > 0 && remainingHours > 0:
		return fmt.Sprintf("%dd%dh", days, remainingHours)
	case days > 0:
		return fmt.Sprintf("%dd", days)
	default:
		return fmt.Sprintf("%dh", hours)
	}
}

// ParseDuration parses a duration string that supports days (e.g., "7d", "168h", "1d12h").
// Supports combined forms like "1d2m" and "1d1.5h". Rejects negative durations.
func ParseDuration(s string) (time.Duration, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return 0, errors.New("empty duration")
	}
	if strings.Contains(trimmed, "-") {
		return 0, fmt.Errorf("invalid duration (negative): %s", s)
	}

	normalized, err := normalizeDaysToHours(trimmed)
	if err != nil {
		return 0, err
	}

	dur, err := time.ParseDuration(normalized)
	if err != nil {
		return 0, err
	}
	if dur < 0 {
		return 0, fmt.Errorf("invalid duration (negative): %s", s)
	}
	return dur, nil
}

func normalizeDaysToHours(s string) (string, error) {
	if !strings.Contains(strings.ToLower(s), "d") {
		return s, nil
	}

	var convErr error
	normalized := dayTokenPattern.ReplaceAllStringFunc(s, func(token string) string {
		if convErr != nil {
			return token
		}
		dayValue := token[:len(token)-1] // remove trailing d/D
		days, err := strconv.ParseFloat(dayValue, 64)
		if err != nil {
			convErr = fmt.Errorf("invalid day component: %q", dayValue)
			return token
		}
		hours := days * hoursPerDay
		return strconv.FormatFloat(hours, 'f', -1, 64) + "h"
	})
	if convErr != nil {
		return "", convErr
	}
	return normalized, nil
}
