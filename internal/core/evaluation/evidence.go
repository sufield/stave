package evaluation

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// RootCause represents the high-level mechanism causing a violation.
type RootCause string

const (
	// RootCauseIdentity indicates an identity-bound policy (e.g., IAM, RBAC) is the cause.
	RootCauseIdentity RootCause = "identity"
	// RootCauseResource indicates a resource-bound policy (e.g., Bucket Policy, ACL) is the cause.
	RootCauseResource RootCause = "resource"
	// RootCauseGeneral indicates misconfigurations exist but none are categorized.
	RootCauseGeneral RootCause = "general"
)

func (rc RootCause) String() string {
	return string(rc)
}

// Evidence contains the audit-ready proof of a violation.
//
// Fields are conditionally populated based on the control type:
//   - Duration: FirstUnsafeAt, LastSeenUnsafeAt, UnsafeDurationHours, ThresholdHours
//   - Recurrence: ExposureWindowCount, WindowDays, RecurrenceThreshold, FirstExposureWindowAt, LastExposureWindowAt
type Evidence struct {
	// --- Duration Timing ---
	FirstUnsafeAt       time.Time `json:"first_unsafe_at,omitzero"`
	LastSeenUnsafeAt    time.Time `json:"last_seen_unsafe_at,omitzero"`
	UnsafeDurationHours float64   `json:"unsafe_duration_hours,omitempty"`
	ThresholdHours      float64   `json:"threshold_hours,omitempty"`

	// --- Recurrence Frequency ---
	ExposureWindowCount   int       `json:"exposure_window_count,omitempty"`
	WindowDays            int       `json:"window_days,omitempty"`
	RecurrenceThreshold   int       `json:"recurrence_threshold,omitempty"`
	FirstExposureWindowAt time.Time `json:"first_exposure_window_at,omitzero"`
	LastExposureWindowAt  time.Time `json:"last_exposure_window_at,omitzero"`

	// --- Logical Evidence ---
	Misconfigurations []policy.Misconfiguration `json:"misconfigurations,omitempty"`
	RootCauses        []RootCause               `json:"root_causes,omitempty"`
	SourceEvidence    *SourceEvidence           `json:"source_evidence,omitempty"`

	// TemporalRisk is a human-readable summary of the current violation state.
	TemporalRisk string `json:"temporal_risk,omitempty"`

	// EvidenceInvalid is set when the strategy could not produce a
	// faithful Evidence record but emitted a finding anyway —
	// typically because duration math failed and the strategy
	// fell back to a sentinel duration of -1.0. Consumers that
	// surface evidence in reports should treat the row as
	// "violation confirmed, evidence unreliable" and avoid
	// performing arithmetic on UnsafeDurationHours when this is
	// true. The earlier shape only logged the underlying error,
	// so downstream rendering had no way to distinguish a real
	// duration from the sentinel.
	EvidenceInvalid bool `json:"evidence_invalid,omitempty"`
}

// HasTemporalRisk reports whether the evidence carries a human-
// readable temporal-risk summary string. Replaces the
// (e.TemporalRisk != "") probe at renderer call sites.
func (e Evidence) HasTemporalRisk() bool {
	return e.TemporalRisk != ""
}

// TemporalSnapshot bundles the four temporal fields downstream
// projections need together. Centralised so diagnose / DTO mappers
// stop reading FirstUnsafeAt / LastSeenUnsafeAt /
// UnsafeDurationHours / ThresholdHours individually — one method
// keeps "what's the temporal posture of this evidence?" on the
// type that owns the fields.
type TemporalSnapshot struct {
	FirstUnsafeAt       time.Time
	LastSeenUnsafeAt    time.Time
	UnsafeDurationHours float64
	ThresholdHours      float64
}

// TemporalSnapshot returns the (first / last / duration / threshold)
// projection callers need to seed temporal-aware DTOs without
// reaching into the four fields directly.
func (e Evidence) TemporalSnapshot() TemporalSnapshot {
	return TemporalSnapshot{
		FirstUnsafeAt:       e.FirstUnsafeAt,
		LastSeenUnsafeAt:    e.LastSeenUnsafeAt,
		UnsafeDurationHours: e.UnsafeDurationHours,
		ThresholdHours:      e.ThresholdHours,
	}
}

// HasDiscoveryDate reports whether the snapshot recorded a first-
// unsafe timestamp — i.e. we know when this state transition
// occurred. Renderers gate the "First unsafe:" line on this so the
// section reads as business intent rather than a (!IsZero()) probe.
func (s TemporalSnapshot) HasDiscoveryDate() bool {
	return !s.FirstUnsafeAt.IsZero()
}

// HasRecentActivity reports whether the snapshot recorded a
// last-seen-unsafe timestamp — i.e. the violation was observed in a
// later snapshot than the first sighting. Same intent-revealing
// shape as HasDiscoveryDate.
func (s TemporalSnapshot) HasRecentActivity() bool {
	return !s.LastSeenUnsafeAt.IsZero()
}

// IsDurationTracked reports whether the snapshot has a measured
// dwell time. The threshold is `> 0` so degenerate fractional
// durations (sub-second blip on a freshly-created resource) still
// count, but a zero-duration unanchored finding is treated as
// "not yet tracked" and the renderer skips the row.
func (s TemporalSnapshot) IsDurationTracked() bool {
	return s.UnsafeDurationHours > 0
}

// HasMisconfigurations reports whether the evidence carries any
// per-clause misconfiguration entries. Replaces the
// (len(e.Misconfigurations) > 0) probe.
func (e Evidence) HasMisconfigurations() bool {
	return len(e.Misconfigurations) > 0
}

// HasSourceEvidence reports whether the evidence carries a
// pointer to specific configuration entries (SIDs, grantees).
// Replaces the (e.SourceEvidence != nil) probe.
func (e Evidence) HasSourceEvidence() bool {
	return e.SourceEvidence != nil
}

// HasLifecycleDates reports whether the evidence has a recorded
// FirstUnsafeAt or LastSeenUnsafeAt timestamp. Replaces the
// (!e.FirstUnsafeAt.IsZero() || !e.LastSeenUnsafeAt.IsZero())
// compound check at renderer sites.
func (e Evidence) HasLifecycleDates() bool {
	return !e.FirstUnsafeAt.IsZero() || !e.LastSeenUnsafeAt.IsZero()
}

// HasExposureWindows reports whether the evidence's recurrence
// counter is non-zero (the asset went unsafe at least once in
// the recurrence window). Replaces the
// (e.ExposureWindowCount > 0) probe.
func (e Evidence) HasExposureWindows() bool {
	return e.ExposureWindowCount > 0
}

// RootCauseStrings converts typed causes to a raw string slice.
func (e Evidence) RootCauseStrings() []string {
	if len(e.RootCauses) == 0 {
		return nil
	}
	out := make([]string, len(e.RootCauses))
	for i, rc := range e.RootCauses {
		out[i] = string(rc)
	}
	return out
}

// SourceEvidence provides pointers to specific configuration entries (e.g. SIDs, Grantees).
type SourceEvidence struct {
	// IdentityStatements lists IDs/indices of identity-bound policies (e.g., IAM SIDs).
	IdentityStatements []kernel.StatementID `json:"identity_statements,omitempty"`
	// ResourceGrantees lists specific entities granted access via resource-bound policies (e.g., ACL URIs).
	ResourceGrantees []kernel.GranteeID `json:"resource_grantees,omitempty"`
}

// DriftPattern classifies the temporal behavior of a violation.
type DriftPattern string

const (
	// DriftPersistent indicates the asset has been unsafe since the very first observation.
	DriftPersistent DriftPattern = "persistent"
	// DriftDegraded indicates the asset was safe initially but has since entered an unsafe state.
	DriftDegraded DriftPattern = "degraded"
	// DriftIntermittent indicates the asset has toggled between safe and unsafe multiple times.
	DriftIntermittent DriftPattern = "intermittent"
)

// IsValid reports whether the value is one of the recognized drift
// patterns. Used by callers that have a DriftPattern in hand and
// need to confirm it before branching.
func (d DriftPattern) IsValid() bool {
	switch d {
	case DriftPersistent, DriftDegraded, DriftIntermittent:
		return true
	}
	return false
}

// String returns the canonical lowercase name.
func (d DriftPattern) String() string { return string(d) }

// ParseDriftPattern returns a validated DriftPattern. Empty input is
// rejected; the caller can model "no drift recorded" by leaving the
// PostureDrift.Pattern field at the zero value rather than passing
// an empty string through ParseDriftPattern.
func ParseDriftPattern(raw string) (DriftPattern, error) {
	d := DriftPattern(raw)
	if !d.IsValid() {
		return "", fmt.Errorf("invalid drift pattern %q: must be one of persistent, degraded, intermittent", raw)
	}
	return d, nil
}

// UnmarshalText implements encoding.TextUnmarshaler so JSON / YAML
// unmarshal paths share a single validation gate.
func (d *DriftPattern) UnmarshalText(text []byte) error {
	parsed, err := ParseDriftPattern(string(text))
	if err != nil {
		return err
	}
	*d = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d DriftPattern) MarshalText() ([]byte, error) {
	return []byte(d.String()), nil
}

// MarshalJSON serializes the pattern as a JSON string.
func (d DriftPattern) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON delegates to UnmarshalText for boundary validation.
func (d *DriftPattern) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return d.UnmarshalText([]byte(s))
}

// UnmarshalYAML lets gopkg.in/yaml.v3 round-trip drift patterns
// through the same validation as JSON. The yaml.v3 decoder hands us
// a node-decode callback; treat the value as a string and delegate.
func (d *DriftPattern) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return d.UnmarshalText([]byte(s))
}

// PostureDrift describes how a violation has evolved over time.
type PostureDrift struct {
	Pattern             DriftPattern `json:"pattern"`
	ExposureWindowCount int          `json:"exposure_window_count"`
}

// ComputePostureDrift analyzes a lifecycle to classify the violation's drift pattern.
// Returns nil if the asset is not currently in an unsafe state.
//
// The classification logic lives on asset.ExposureLifecycle.DriftFacts;
// this function wraps the raw (pattern string, episodes int) pair into
// the typed DriftPattern / PostureDrift wire shape so callers in
// evaluation continue to receive the typed result.
func ComputePostureDrift(t *asset.ExposureLifecycle) *PostureDrift {
	pattern, episodes := t.DriftFacts()
	if pattern == "" {
		return nil
	}
	return &PostureDrift{
		Pattern:             DriftPattern(pattern),
		ExposureWindowCount: episodes,
	}
}
