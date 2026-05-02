package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// SLAPolicySource records the provenance of an SLA deadline that was
// applied to a Finding. The vocabulary is closed at the type level
// for the fixed sources (control override) but open-ended for
// profile-based sources, which carry an arbitrary profile name in a
// "profile:<id>" form.
//
// Constants below name every fixed source; profile sources should be
// constructed via SLAPolicySourceProfile so the prefix stays
// consistent across writers.
type SLAPolicySource string

// Closed-vocabulary constants for SLAPolicySource. Use these instead
// of open-coding the strings at every call site so a typo at
// construction time becomes a compile error rather than a silent
// "unknown source" downstream.
const (
	// SLAPolicySourceUnset is the zero value, distinguishing "no SLA
	// policy applied" from any explicit source.
	SLAPolicySourceUnset SLAPolicySource = ""

	// SLAPolicySourceControlOverride records that the SLA deadline
	// came from a control-level override (control YAML's
	// sla_deadline field), taking precedence over the profile.
	SLAPolicySourceControlOverride SLAPolicySource = "control_override"

	// slaPolicySourceProfilePrefix is the prefix used by
	// SLAPolicySourceProfile so the "profile:<id>" form has one
	// canonical writer. Not exported — callers go through
	// SLAPolicySourceProfile.
	slaPolicySourceProfilePrefix = "profile:"
)

// SLAPolicySourceProfile constructs a profile-based SLA source for
// the given profile ID, e.g. SLAPolicySourceProfile("default") →
// "profile:default". Centralised so the prefix is written once.
func SLAPolicySourceProfile(profileID string) SLAPolicySource {
	return SLAPolicySource(slaPolicySourceProfilePrefix + profileID)
}

// String returns the raw source string.
func (s SLAPolicySource) String() string { return string(s) }

// IsEmpty reports whether the source is unset (no SLA policy
// applied). Distinct from IsValid — IsEmpty answers "was a source
// recorded?" while IsValid answers "is the recorded source one we
// recognise?".
func (s SLAPolicySource) IsEmpty() bool { return s == SLAPolicySourceUnset }

// IsValid reports whether the source matches one of the known
// shapes: empty (zero value), the SLAPolicySourceControlOverride
// constant, or a "profile:<id>" form with a non-empty profile ID.
func (s SLAPolicySource) IsValid() bool {
	if s == SLAPolicySourceUnset || s == SLAPolicySourceControlOverride {
		return true
	}
	if rest, ok := strings.CutPrefix(string(s), slaPolicySourceProfilePrefix); ok {
		return rest != ""
	}
	return false
}

// IsProfile reports whether the source carries a profile reference.
// The profile ID is everything after the "profile:" prefix.
func (s SLAPolicySource) IsProfile() bool {
	if !strings.HasPrefix(string(s), slaPolicySourceProfilePrefix) {
		return false
	}
	return len(string(s)) > len(slaPolicySourceProfilePrefix)
}

// ProfileID returns the profile portion of a profile-based source,
// or empty string when the source isn't profile-shaped.
func (s SLAPolicySource) ProfileID() string {
	if !s.IsProfile() {
		return ""
	}
	return string(s)[len(slaPolicySourceProfilePrefix):]
}

// UnmarshalText delegates to a single validation gate so JSON / YAML
// inputs reject malformed values at the boundary.
func (s *SLAPolicySource) UnmarshalText(text []byte) error {
	candidate := SLAPolicySource(text)
	if !candidate.IsValid() {
		return fmt.Errorf("invalid SLA policy source %q: must be empty, %q, or profile:<id>",
			string(text), string(SLAPolicySourceControlOverride))
	}
	*s = candidate
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (s SLAPolicySource) MarshalText() ([]byte, error) {
	if !s.IsValid() {
		return nil, errors.New("invalid SLA policy source")
	}
	return []byte(s.String()), nil
}

// MarshalJSON serializes as a JSON string.
func (s SLAPolicySource) MarshalJSON() ([]byte, error) {
	if !s.IsValid() {
		return nil, errors.New("invalid SLA policy source")
	}
	return json.Marshal(s.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (s *SLAPolicySource) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	return s.UnmarshalText([]byte(raw))
}
