package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity represents the severity level of an control or finding.
// Constants are ordered by iota so that Gte is a simple integer comparison.
type Severity int

const (
	SeverityNone     Severity = iota
	SeverityInfo              // 1
	SeverityLow               // 2
	SeverityMedium            // 3
	SeverityHigh              // 4
	SeverityCritical          // 5
)

// String provides the wire-format name.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return ""
	}
}

// IsValid reports whether s is a recognized severity level.
func (s Severity) IsValid() bool {
	return s >= SeverityInfo && s <= SeverityCritical
}

// Gte reports whether s is greater than or equal to other in severity rank.
func (s Severity) Gte(other Severity) bool {
	return s >= other
}

// ParseSeverity converts a string to a Severity value.
func ParseSeverity(s string) Severity {
	switch strings.ToLower(s) {
	case "info":
		return SeverityInfo
	case "low":
		return SeverityLow
	case "medium":
		return SeverityMedium
	case "high":
		return SeverityHigh
	case "critical":
		return SeverityCritical
	default:
		return SeverityNone
	}
}

// MarshalJSON writes the severity as its string name.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON reads a severity string into the ordinal value.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed := ParseSeverity(str)
	if str != "" && parsed == SeverityNone {
		return fmt.Errorf("unknown severity %q", str)
	}
	*s = parsed
	return nil
}

// MarshalYAML writes the severity as its string name.
func (s Severity) MarshalYAML() (any, error) {
	return s.String(), nil
}

// UnmarshalYAML reads a severity string into the ordinal value.
func (s *Severity) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	parsed := ParseSeverity(str)
	if str != "" && parsed == SeverityNone {
		return fmt.Errorf("unknown severity %q", str)
	}
	*s = parsed
	return nil
}
