package controldef

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Severity represents the criticality level of a security control or finding.
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

// String returns the canonical lowercase name of the severity.
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

// IsValid reports whether s is a recognized severity level (excluding None).
func (s Severity) IsValid() bool {
	return s >= SeverityInfo && s <= SeverityCritical
}

// Gte reports whether s is greater than or equal to other in severity rank.
func (s Severity) Gte(other Severity) bool {
	return s >= other
}

// ParseSeverity converts a string into a Severity level.
// It is case-insensitive and returns an error for unrecognized strings.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	case "none", "":
		return SeverityNone, nil
	default:
		return SeverityNone, fmt.Errorf("invalid severity level %q", s)
	}
}

// --- Serialization Primitives ---

// MarshalText implements encoding.TextMarshaler for consistent output
// across all text-based serialization formats.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler for consistent input
// across all text-based serialization formats.
func (s *Severity) UnmarshalText(text []byte) error {
	parsed, err := ParseSeverity(string(text))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// --- Format-Specific Overrides ---

// MarshalJSON ensures the string representation is used in JSON.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON parses a JSON string into the ordinal value.
func (s *Severity) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	return s.UnmarshalText([]byte(str))
}

// MarshalYAML returns the string representation for YAML output.
func (s Severity) MarshalYAML() (any, error) {
	return s.String(), nil
}

// UnmarshalYAML parses a YAML string into the ordinal value.
func (s *Severity) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	return s.UnmarshalText([]byte(str))
}
