package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ControlType represents a canonical control check type.
// Constants are ordered by iota so that IsValid is a simple range check.
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
	TypeK8sRbacSecurity                   // 10
)

var controlTypeNames = map[ControlType]string{
	TypeUnsafeState:           "unsafe_state",
	TypeUnsafeDuration:        "unsafe_duration",
	TypeUnsafeRecurrence:      "unsafe_recurrence",
	TypeAuthorizationBoundary: "authorization_boundary",
	TypeAudienceBoundary:      "audience_boundary",
	TypeJustificationRequired: "justification_required",
	TypeOwnershipRequired:     "ownership_required",
	TypeVisibilityRequired:    "visibility_required",
	TypePrefixExposure:        "prefix_exposure",
	TypeK8sRbacSecurity:       "k8s_rbac_security",
}

var controlTypeByName = map[string]ControlType{
	"unsafe_state":           TypeUnsafeState,
	"unsafe_duration":        TypeUnsafeDuration,
	"unsafe_recurrence":      TypeUnsafeRecurrence,
	"authorization_boundary": TypeAuthorizationBoundary,
	"audience_boundary":      TypeAudienceBoundary,
	"justification_required": TypeJustificationRequired,
	"ownership_required":     TypeOwnershipRequired,
	"visibility_required":    TypeVisibilityRequired,
	"prefix_exposure":        TypePrefixExposure,
	"k8s_rbac_security":      TypeK8sRbacSecurity,
}

// String provides the wire-format name.
func (t ControlType) String() string {
	return controlTypeNames[t]
}

// IsValid reports whether t is a recognized canonical control type.
func (t ControlType) IsValid() bool {
	return t >= TypeUnsafeState && t <= TypeK8sRbacSecurity
}

// ParseControlType converts a string to a ControlType value.
func ParseControlType(s string) ControlType {
	if parsed, ok := controlTypeByName[strings.TrimSpace(s)]; ok {
		return parsed
	}
	return TypeUnknown
}

// MarshalJSON writes the type as its string name.
func (t ControlType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON reads a type string into the ordinal value.
func (t *ControlType) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	parsed := ParseControlType(str)
	if str != "" && parsed == TypeUnknown {
		return fmt.Errorf("unknown control type %q", str)
	}
	*t = parsed
	return nil
}

// MarshalYAML writes the type as its string name.
func (t ControlType) MarshalYAML() (any, error) {
	return t.String(), nil
}

// UnmarshalYAML reads a type string into the ordinal value.
func (t *ControlType) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	parsed := ParseControlType(str)
	if str != "" && parsed == TypeUnknown {
		return fmt.Errorf("unknown control type %q", str)
	}
	*t = parsed
	return nil
}
