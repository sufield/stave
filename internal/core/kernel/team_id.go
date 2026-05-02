package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// TeamID identifies an ownership team for a finding (the team
// responsible for remediation). Mirrors asset.ID's validation
// shape: trimmed, non-empty, no control characters, no surrounding
// whitespace.
type TeamID string

// String returns the raw ID.
func (t TeamID) String() string { return string(t) }

// IsEmpty reports whether the ID is unset.
func (t TeamID) IsEmpty() bool { return t == "" }

// validateTeamIDRaw checks the structural invariants without taking
// ownership of the string — used by both NewTeamID and the unmarshal
// paths so all entry points share one gate.
func validateTeamIDRaw(raw string) error {
	for _, r := range raw {
		if unicode.IsControl(r) {
			return fmt.Errorf("team id %q contains control characters", raw)
		}
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("team id must not be empty")
	}
	if trimmed != raw {
		return fmt.Errorf("team id %q must not have leading or trailing whitespace", raw)
	}
	return nil
}

// NewTeamID returns a validated TeamID.
func NewTeamID(raw string) (TeamID, error) {
	if err := validateTeamIDRaw(raw); err != nil {
		return "", err
	}
	return TeamID(raw), nil
}

// UnmarshalText delegates to NewTeamID so JSON / YAML / text inputs
// share one validation gate.
func (t *TeamID) UnmarshalText(text []byte) error {
	parsed, err := NewTeamID(string(text))
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (t TeamID) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// MarshalJSON serialises as a JSON string.
func (t TeamID) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON delegates to UnmarshalText.
func (t *TeamID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return t.UnmarshalText([]byte(s))
}
