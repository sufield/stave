package controldef

import (
	"cmp"
	"encoding/json"
	"fmt"
	"strings"
)

// Severity represents the criticality level of a security control or finding.
// Constants are ordered by iota so that Gte is a simple integer comparison.
type Severity int

// Severity level constants ordered from least to most critical.
const (
	SeverityNone     Severity = iota
	SeverityInfo              // 1
	SeverityLow               // 2
	SeverityMedium            // 3
	SeverityHigh              // 4
	SeverityCritical          // 5
)

// severityCodec is the canonical String/Parse pair for Severity.
// Case-insensitive on Decode so "Critical" and "CRITICAL" parse the
// same as "critical" — matches the prior ParseSeverity behavior.
var severityCodec = NewEnumCodec(true, map[Severity]string{
	SeverityInfo:     "info",
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
})

// String returns the canonical lowercase name of the severity.
func (s Severity) String() string {
	return severityCodec.Encode(s)
}

// IsValid reports whether s is a recognized severity level (excluding None).
func (s Severity) IsValid() bool {
	return s >= SeverityInfo && s <= SeverityCritical
}

// IsSet reports whether s carries a non-zero (i.e. non-SeverityNone)
// rank. Used by selectors and filters that treat the zero value as
// "no severity requested" — replaces (s > SeverityNone) probes at
// the call site with an intent-named check.
func (s Severity) IsSet() bool {
	return s > SeverityNone
}

// Matches reports whether s renders to the same canonical name as
// the given string, case-insensitively. Replaces the
// strings.EqualFold(s.String(), other) probe in catalogsearch and
// similar callers so the comparison logic stays on the type that
// owns the canonical form.
func (s Severity) Matches(other string) bool {
	return strings.EqualFold(s.String(), other)
}

// Compare returns -1, 0, or +1 comparing severity rank.
func (s Severity) Compare(other Severity) int {
	return cmp.Compare(int(s), int(other))
}

// Gte reports whether s is greater than or equal to other in severity rank.
func (s Severity) Gte(other Severity) bool {
	return s >= other
}

// Weight returns the integer base score used by exposure ranking and
// risk-priority calculations when a control does not define
// base_impact in its params.
//
// NormalizedWeight returns the four-tier (1.0 — 4.0) severity scale
// the execreport top-findings ranker uses. Distinct from Weight,
// which returns the 25/50/75/100 scale used by exposure scoring.
// Centralised here so callers stop reproducing the local
// {"critical":4, "high":3, "medium":2, "low":1} map.
func (s Severity) NormalizedWeight() float64 {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Centralised on the Severity type so risk and rank packages do not
// each open-code the same Critical=100/High=75/Medium=50/Low=25
// switch — see exposure_rank.go, app/rank/identity.go,
// app/rank/priority.go, app/consolidate/consolidate.go.
func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 75
	case SeverityMedium:
		return 50
	case SeverityLow:
		return 25
	default:
		return 10
	}
}

// BucketName returns the canonical lowercase bucket name used by
// severity-rollup callers (severity_counts, monitor data, exec
// reports, team-gate, consolidate). For the recognized severity
// levels it matches String(); SeverityNone falls back to "info" so
// every callable bucket has a name and the call sites do not need a
// "default" branch.
func (s Severity) BucketName() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
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
