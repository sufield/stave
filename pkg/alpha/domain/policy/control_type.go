package policy

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

// String returns the wire-format name of the control type.
func (t ControlType) String() string {
	switch t {
	case TypeUnsafeState:
		return "unsafe_state"
	case TypeUnsafeDuration:
		return "unsafe_duration"
	case TypeUnsafeRecurrence:
		return "unsafe_recurrence"
	case TypeAuthorizationBoundary:
		return "authorization_boundary"
	case TypeAudienceBoundary:
		return "audience_boundary"
	case TypeJustificationRequired:
		return "justification_required"
	case TypeOwnershipRequired:
		return "ownership_required"
	case TypeVisibilityRequired:
		return "visibility_required"
	case TypePrefixExposure:
		return "prefix_exposure"
	default:
		return "unknown"
	}
}

// IsValid reports whether t is a recognized canonical control type.
func (t ControlType) IsValid() bool {
	return t > TypeUnknown && t <= TypePrefixExposure
}

// ParseControlType converts a string name into a ControlType.
func ParseControlType(s string) (ControlType, error) {
	norm := strings.TrimSpace(strings.ToLower(s))
	switch norm {
	case "unsafe_state":
		return TypeUnsafeState, nil
	case "unsafe_duration":
		return TypeUnsafeDuration, nil
	case "unsafe_recurrence":
		return TypeUnsafeRecurrence, nil
	case "authorization_boundary":
		return TypeAuthorizationBoundary, nil
	case "audience_boundary":
		return TypeAudienceBoundary, nil
	case "justification_required":
		return TypeJustificationRequired, nil
	case "ownership_required":
		return TypeOwnershipRequired, nil
	case "visibility_required":
		return TypeVisibilityRequired, nil
	case "prefix_exposure":
		return TypePrefixExposure, nil
	case "", "unknown":
		return TypeUnknown, nil
	default:
		return TypeUnknown, fmt.Errorf("unknown control type %q", s)
	}
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
