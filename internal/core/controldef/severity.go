package controldef

import (
	"cmp"
	"encoding/json"
	"fmt"
	"log/slog"
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
// MeetsThreshold reports whether this severity is at or above the
// given minimum threshold on the canonical iota ladder
// (None < Info < Low < Medium < High < Critical). Renderers and
// export filters route "include if severity ≥ threshold" through
// this so the comparison reads as a domain rule, not an integer
// inequality.
func (s Severity) MeetsThreshold(threshold Severity) bool {
	return s >= threshold
}

// IsLowerThan reports whether this severity falls below the given
// threshold. Designed for the "skip-fast" guard pattern in
// filtering loops — `if rec.Severity.IsLowerThan(min) { continue }`
// reads linearly without the double-negative friction of
// `!MeetsThreshold`.
func (s Severity) IsLowerThan(threshold Severity) bool {
	return s < threshold
}

// SARIFLevel returns the SARIF v2.1.0 result-level string the
// GitHub Code Scanning surface expects: Critical/High → "error",
// Medium → "warning", everything else → "note". Centralised so
// the SARIF writer stops carrying its own mapSeverityToSarif copy.
func (s Severity) SARIFLevel() string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// NormalizedWeight returns the four-tier (1.0 — 4.0) severity scale
// the severity-score and execreport top-findings ranker use.
// Distinct from Weight, which returns the 25/50/75/100 scale used by
// exposure scoring. Centralised here so callers stop reproducing the
// local {"critical":4, "high":3, "medium":2, "low":1} map.
//
// Severities outside the reportable bucket (None / Info / unknown)
// floor at 1.0 so every finding contributes positive exposure to the
// score. This is a domain policy: the loop callers must not
// "correct" the value with a local `if sw == 0` check — keep the
// flooring on the type so a future tier change (e.g. Info → 0.5)
// lands at one site.
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
		return 1
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

// Bump escalates this severity by n tiers along the
// Low → Medium → High → Critical ladder, capped at Critical. Severities
// outside the escalation ladder (None, Info) are returned unchanged so
// callers can call Bump unconditionally.
//
// Centralised here so the SLA engine and any future caller share a
// single ladder instead of each open-coding the (low → medium → high
// → critical) progression.
func (s Severity) Bump(n int) Severity {
	if n <= 0 {
		return s
	}
	ladder := []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	idx := -1
	for i, lvl := range ladder {
		if lvl == s {
			idx = i
			break
		}
	}
	if idx < 0 {
		return s
	}
	target := idx + n
	if target >= len(ladder) {
		target = len(ladder) - 1
	}
	return ladder[target]
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
	switch s {
	case "info", "INFO", "Info":
		return SeverityInfo, nil
	case "low", "LOW", "Low":
		return SeverityLow, nil
	case "medium", "MEDIUM", "Medium":
		return SeverityMedium, nil
	case "high", "HIGH", "High":
		return SeverityHigh, nil
	case "critical", "CRITICAL", "Critical":
		return SeverityCritical, nil
	case "none", "NONE", "None", "":
		return SeverityNone, nil
	}
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

// ParseSeverityLax wraps ParseSeverity for boundary code (export
// adapters, evidence-record loaders) that needs to keep going on
// an unrecognised severity rather than failing the run. On error
// it returns SeverityNone and logs at WARN with the supplied
// context map (control_id, resource_arn, etc.) appended to the
// log key/value pairs so operators see which row produced the
// malformed severity.
//
// Logger may be nil — in that case the warn is silently dropped,
// which matches the prior cmd-side fallback behaviour.
func ParseSeverityLax(val string, logger *slog.Logger, context map[string]string) Severity {
	sev, err := ParseSeverity(val)
	if err != nil && logger != nil {
		args := []any{"severity", val, "error", err}
		for k, v := range context {
			args = append(args, k, v)
		}
		logger.Warn("unrecognised severity; defaulting to none", args...)
	}
	return sev
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
