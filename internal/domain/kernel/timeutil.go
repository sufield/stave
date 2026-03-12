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

var (
	// ErrEmptyDuration is returned when parsing an empty or whitespace-only string.
	ErrEmptyDuration = errors.New("empty duration string")

	// dayTokenPattern matches digits (integer or float) followed by 'd'.
	dayTokenPattern = regexp.MustCompile(`(?i)([\d\.]+)[d]`)
)

const hoursPerDay = 24

// Duration wraps time.Duration to provide human-readable serialization (e.g., "7d", "24h").
// Unlike standard time.Duration, this type serializes as a string in JSON/YAML.
type Duration time.Duration

// Std converts the value back to a standard time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String returns a compact human-readable representation (e.g., "7d" or "1h").
func (d Duration) String() string { return FormatDuration(time.Duration(d)) }

// --- Serialization Interfaces ---

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return d.parseAndAssign(s)
}

// MarshalYAML implements the YAML marshaler interface.
func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

// UnmarshalYAML implements the YAML unmarshaler interface.
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return d.parseAndAssign(s)
}

func (d *Duration) parseAndAssign(s string) error {
	parsed, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// --- Formatting ---

// FormatDuration formats a duration for CLI flags and evidence strings.
// Uses days when evenly divisible by 24 hours, otherwise hours.
func FormatDuration(d time.Duration) string {
	h := d.Hours()
	if h == 0 {
		return "0h"
	}
	// If it's a whole number of days, use 'd'
	if h >= hoursPerDay && float64(int64(h)) == h && int64(h)%hoursPerDay == 0 {
		return fmt.Sprintf("%dd", int64(h)/hoursPerDay)
	}
	return fmt.Sprintf("%gh", h)
}

// FormatDurationHuman formats a duration for human display.
// Shows compound form like "2d6h" when there are remaining hours.
func FormatDurationHuman(d time.Duration) string {
	hTotal := int64(d.Hours())
	if hTotal == 0 {
		return "0h"
	}
	days := hTotal / hoursPerDay
	hrs := hTotal % hoursPerDay

	if days > 0 && hrs > 0 {
		return fmt.Sprintf("%dd%dh", days, hrs)
	}
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dh", hTotal)
}

// --- Parsing ---

// ParseDuration parses strings like "7d", "1.5d", "1d12h", or "168h".
// It is a wrapper around time.ParseDuration that adds support for the 'd' (day) unit.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, ErrEmptyDuration
	}
	if strings.HasPrefix(s, "-") {
		return 0, fmt.Errorf("negative duration not allowed: %s", s)
	}

	normalized, err := normalizeDaysToHours(s)
	if err != nil {
		return 0, err
	}

	return time.ParseDuration(normalized)
}

func normalizeDaysToHours(s string) (string, error) {
	// Fast path: skip regex if no 'd' exists
	if !strings.Contains(strings.ToLower(s), "d") {
		return s, nil
	}

	var errOccurred error
	result := dayTokenPattern.ReplaceAllStringFunc(s, func(match string) string {
		if errOccurred != nil {
			return match
		}
		val := match[:len(match)-1] // strip trailing 'd'
		days, err := strconv.ParseFloat(val, 64)
		if err != nil {
			errOccurred = fmt.Errorf("invalid day value %q: %w", val, err)
			return match
		}
		return fmt.Sprintf("%gh", days*hoursPerDay)
	})

	return result, errOccurred
}
