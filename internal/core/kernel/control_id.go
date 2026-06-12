package kernel

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ControlID represents a unique, structured identifier for a security control.
// Format: CTL.<PROVIDER>.<CATEGORY...>.<SEQUENCE>
type ControlID string

// controlIDPattern validates the strict canonical format.
// Examples: CTL.STORAGE.PUBLIC.001, CTL.NETWORK.FIREWALL.INGRESS.005
var controlIDPattern = regexp.MustCompile(`^CTL\.[A-Z][A-Z0-9]*(\.[A-Z][A-Z0-9]*){1,}\.\d{3}$`)

// controlIDBasicPattern validates structural soundness at parse time without
// enforcing the full canonical format. Requires dot-separated uppercase/digit
// segments (2+ segments). Catches clearly invalid values (lowercase, special
// chars, spaces) while allowing non-CTL prefixes (e.g. HIPAA: ACCESS.001).
var controlIDBasicPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(\.[A-Z0-9]+)+$`)

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
	s := id.String()
	_, rest, ok := strings.Cut(s, ".")
	if !ok {
		return ""
	}
	prov, _, _ := strings.Cut(rest, ".")
	return prov
}

// Category extracts the middle functional segments.
// For "CTL.S3.PUBLIC.READ.001", it returns "PUBLIC.READ".
func (id ControlID) Category() string {
	s := id.String()
	_, rest, ok := strings.Cut(s, ".")
	if !ok {
		return ""
	}
	_, rest, ok = strings.Cut(rest, ".")
	if !ok {
		return ""
	}
	idx := strings.LastIndexByte(rest, '.')
	if idx < 0 {
		return rest
	}
	return rest[:idx]
}

// Sequence extracts the trailing numeric identifier.
// For "CTL.S3.PUBLIC.001", it returns "001".
func (id ControlID) Sequence() string {
	s := id.String()
	idx := strings.LastIndexByte(s, '.')
	if idx < 0 {
		return s
	}
	return s[idx+1:]
}

// ValidateControlIDFormat ensures the ID meets naming and structure requirements.
func ValidateControlIDFormat(id string) error {
	if !controlIDPattern.MatchString(id) {
		return fmt.Errorf("invalid control ID %q: must match CTL.<PROVIDER>.<CATEGORY>.<SEQ>", id)
	}
	return nil
}

// UnmarshalText implements encoding.TextUnmarshaler. Both JSON and YAML
// unmarshalers delegate to this method, providing a single parse-time gate.
// Rejects empty strings and structurally invalid values (must be dot-separated
// uppercase segments). The strict canonical format (CTL.PROVIDER.CATEGORY.SEQ)
// is checked in Validate() as a warning — this allows user-authored YAML with
// non-canonical IDs to load while still catching garbage at the boundary.
func (id *ControlID) UnmarshalText(text []byte) error {
	s := string(text)
	if s == "" {
		return errors.New("control ID must not be empty")
	}
	if !controlIDBasicPattern.MatchString(s) {
		return fmt.Errorf("invalid control ID format %q: must be dot-separated uppercase segments (e.g. CTL.S3.PUBLIC.001)", s)
	}
	*id = ControlID(s)
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (id ControlID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// MarshalJSON ensures the ID is serialized as a JSON string.
func (id ControlID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

// UnmarshalJSON extracts the JSON string and delegates to UnmarshalText.
func (id *ControlID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	return id.UnmarshalText([]byte(s))
}
