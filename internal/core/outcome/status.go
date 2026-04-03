// Package outcome provides shared result status types used across
// security audit, schema validation, and system health checks.
package outcome

import (
	"fmt"
	"strings"
)

// Status represents the result of a check or evaluation.
type Status int

const (
	Unknown Status = iota
	Pass
	Warn
	Fail
	Skipped
)

var statusNames = [...]string{"UNKNOWN", "PASS", "WARN", "FAIL", "SKIPPED"}

// String returns the uppercase canonical name.
func (s Status) String() string {
	if int(s) < len(statusNames) {
		return statusNames[s]
	}
	return "UNKNOWN"
}

// Lower returns the lowercase name (for schemas that use lowercase).
func (s Status) Lower() string {
	return strings.ToLower(s.String())
}

// MarshalText implements encoding.TextMarshaler.
func (s Status) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// Accepts both "PASS" and "pass".
func (s *Status) UnmarshalText(text []byte) error {
	parsed, err := ParseStatus(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// ParseStatus converts a case-insensitive string to a Status.
func ParseStatus(s string) (Status, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "PASS":
		return Pass, nil
	case "WARN":
		return Warn, nil
	case "FAIL":
		return Fail, nil
	case "SKIPPED":
		return Skipped, nil
	case "UNKNOWN", "":
		return Unknown, nil
	default:
		return Unknown, fmt.Errorf("invalid status %q", s)
	}
}
