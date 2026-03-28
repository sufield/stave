package controldef

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ControlType represents a canonical check logic category.
type ControlType int

const (
	TypeUnknown               ControlType = iota
	TypeUnsafeState                       // 1
	TypeUnsafeDuration                    // 2
	TypeUnsafeRecurrence                  // 3
	TypeAuthorizationBoundary             // 4
	TypeAudienceBoundary                  // 5
	TypeJustificationRequired             // 6
	TypeOwnershipRequired                 // 7
	TypeVisibilityRequired                // 8
	TypePrefixExposure                    // 9
)

// typeToName is the single source of truth for type↔string mapping.
var typeToName = map[ControlType]string{
	TypeUnsafeState:           "unsafe_state",
	TypeUnsafeDuration:        "unsafe_duration",
	TypeUnsafeRecurrence:      "unsafe_recurrence",
	TypeAuthorizationBoundary: "authorization_boundary",
	TypeAudienceBoundary:      "audience_boundary",
	TypeJustificationRequired: "justification_required",
	TypeOwnershipRequired:     "ownership_required",
	TypeVisibilityRequired:    "visibility_required",
	TypePrefixExposure:        "prefix_exposure",
}

// nameToType provides reverse lookup for parsing.
var nameToType = func() map[string]ControlType {
	m := make(map[string]ControlType, len(typeToName))
	for k, v := range typeToName {
		m[v] = k
	}
	return m
}()

// String returns the wire-format name of the control type.
func (t ControlType) String() string {
	if s, ok := typeToName[t]; ok {
		return s
	}
	return "unknown"
}

// IsValid reports whether t is a recognized canonical control type.
func (t ControlType) IsValid() bool {
	_, ok := typeToName[t]
	return ok
}

// ParseControlType converts a string name into a ControlType.
func ParseControlType(s string) (ControlType, error) {
	norm := strings.TrimSpace(strings.ToLower(s))
	if norm == "" || norm == "unknown" {
		return TypeUnknown, nil
	}
	if t, ok := nameToType[norm]; ok {
		return t, nil
	}
	return TypeUnknown, fmt.Errorf("policy: unknown control type %q", s)
}

// --- Serialization ---

// MarshalText implements encoding.TextMarshaler.
func (t ControlType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (t *ControlType) UnmarshalText(text []byte) error {
	parsed, err := ParseControlType(string(text))
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

// MarshalJSON implements json.Marshaler.
func (t ControlType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (t *ControlType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	return t.UnmarshalText([]byte(s))
}

// MarshalYAML implements the YAML marshaler interface.
func (t ControlType) MarshalYAML() (any, error) {
	return t.String(), nil
}

// UnmarshalYAML implements the YAML unmarshaler interface.
func (t *ControlType) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	return t.UnmarshalText([]byte(s))
}
