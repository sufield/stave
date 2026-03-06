package kernel

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// ControlID is the identity type for Control entities (security controls).
type ControlID string

// controlIDPattern validates the CTL.<DOMAIN>.<CATEGORY...>.<SEQ> format.
// It supports canonical IDs such as:
// - CTL.S3.PUBLIC.001
// - CTL.S3.PUBLIC.LIST.001
// Domain/category tokens are uppercase alphanumeric segments.
var controlIDPattern = regexp.MustCompile(`^CTL\.[A-Z][A-Z0-9]*(\.[A-Z][A-Z0-9]*){1,}\.\d{3}$`)

// String returns the underlying ID string.
func (id ControlID) String() string {
	return string(id)
}

// NewControlID creates a validated control ID.
func NewControlID(raw string) (ControlID, error) {
	if err := ValidateControlIDFormat(raw); err != nil {
		return "", err
	}
	return ControlID(raw), nil
}

// MarshalJSON serializes the ID as a JSON string.
func (id ControlID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// UnmarshalJSON parses and validates a JSON string into a ControlID.
func (id *ControlID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	valid, err := NewControlID(s)
	if err != nil {
		return err
	}
	*id = valid
	return nil
}

// ValidateControlIDFormat checks that a control ID follows the canonical format.
func ValidateControlIDFormat(id string) error {
	if !controlIDPattern.MatchString(id) {
		return fmt.Errorf("invalid control ID format %q: must match CTL.<DOMAIN>.<CATEGORY>.<SEQ>", id)
	}
	return nil
}
