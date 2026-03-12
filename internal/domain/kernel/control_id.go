package kernel

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// ControlID represents a unique, structured identifier for a security control.
// Format: CTL.<PROVIDER>.<CATEGORY...>.<SEQUENCE>
type ControlID string

// controlIDPattern validates the canonical format.
// Examples: CTL.STORAGE.PUBLIC.001, CTL.NETWORK.FIREWALL.INGRESS.005
var controlIDPattern = regexp.MustCompile(`^CTL\.[A-Z][A-Z0-9]*(\.[A-Z][A-Z0-9]*){1,}\.\d{3}$`)

// String returns the raw ID string.
func (id ControlID) String() string {
	return string(id)
}

// NewControlID returns a validated ControlID.
func NewControlID(raw string) (ControlID, error) {
	if err := ValidateControlIDFormat(raw); err != nil {
		return "", err
	}
	return ControlID(raw), nil
}

// Provider extracts the service provider or family (the first segment after CTL).
// For "CTL.S3.PUBLIC.001", it returns "S3".
func (id ControlID) Provider() string {
	parts := strings.Split(id.String(), ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// Category extracts the middle functional segments.
// For "CTL.S3.PUBLIC.READ.001", it returns "PUBLIC.READ".
func (id ControlID) Category() string {
	parts := strings.Split(id.String(), ".")
	if len(parts) < 4 {
		if len(parts) >= 3 {
			return parts[2]
		}
		return ""
	}
	return strings.Join(parts[2:len(parts)-1], ".")
}

// Sequence extracts the trailing numeric identifier.
// For "CTL.S3.PUBLIC.001", it returns "001".
func (id ControlID) Sequence() string {
	parts := strings.Split(id.String(), ".")
	return parts[len(parts)-1]
}

// ValidateControlIDFormat ensures the ID meets naming and structure requirements.
func ValidateControlIDFormat(id string) error {
	if !controlIDPattern.MatchString(id) {
		return fmt.Errorf("invalid control ID %q: must match CTL.<PROVIDER>.<CATEGORY>.<SEQ>", id)
	}
	return nil
}

// MarshalJSON ensures the ID is serialized as a string.
func (id ControlID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// UnmarshalJSON validates the ID during deserialization.
func (id *ControlID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	val, err := NewControlID(s)
	if err != nil {
		return err
	}

	*id = val
	return nil
}
