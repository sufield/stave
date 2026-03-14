package kernel

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TrustBoundary classifies the network/identity boundary of an access exposure.
type TrustBoundary int

const (
	BoundaryUnknown      TrustBoundary = iota
	BoundaryExternal                   // Reachable by anyone (public or authenticated cloud users)
	BoundaryCrossAccount               // Reachable by other AWS accounts
	BoundaryInternal                   // Reachable only within the owning account
)

// String returns the canonical wire-format label for the boundary.
func (b TrustBoundary) String() string {
	switch b {
	case BoundaryExternal:
		return "external"
	case BoundaryCrossAccount:
		return "cross_account"
	case BoundaryInternal:
		return "internal"
	default:
		return "unknown"
	}
}

// ParseTrustBoundary converts a string label into its typed TrustBoundary.
// It is case-insensitive and handles leading/trailing whitespace.
func ParseTrustBoundary(raw string) (TrustBoundary, error) {
	norm := strings.TrimSpace(strings.ToLower(raw))
	switch norm {
	case "unknown", "":
		return BoundaryUnknown, nil
	case "external":
		return BoundaryExternal, nil
	case "cross_account":
		return BoundaryCrossAccount, nil
	case "internal":
		return BoundaryInternal, nil
	default:
		return BoundaryUnknown, fmt.Errorf("invalid trust boundary: %q", raw)
	}
}

// MarshalJSON implements the json.Marshaler interface.
func (b TrustBoundary) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (b *TrustBoundary) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	return b.assign(str)
}

// MarshalYAML implements the yaml.Marshaler interface.
func (b TrustBoundary) MarshalYAML() (any, error) {
	return b.String(), nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (b *TrustBoundary) UnmarshalYAML(unmarshal func(any) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	return b.assign(str)
}

// assign is a private helper to update the enum value from a string.
func (b *TrustBoundary) assign(raw string) error {
	parsed, err := ParseTrustBoundary(raw)
	if err != nil {
		return err
	}
	*b = parsed
	return nil
}
