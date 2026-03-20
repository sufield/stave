package kernel

import (
	"encoding/json"
	"errors"
	"strings"
)

// Vendor represents a normalized identifier for a cloud or infrastructure provider.
// Example: "aws", "gcp", "azure", "onprem".
type Vendor string

// String returns the string representation of the vendor.
func (v Vendor) String() string {
	if v == "" {
		return "unknown"
	}
	return string(v)
}

// NewVendor normalizes and validates a raw string into a Vendor type.
// It enforces lowercase and trims whitespace to ensure consistency across the domain.
func NewVendor(raw string) (Vendor, error) {
	v := Vendor(strings.ToLower(strings.TrimSpace(raw)))
	if v == "" {
		return "", errors.New("vendor identifier cannot be empty")
	}
	return v, nil
}

// UnmarshalJSON normalizes and validates the vendor during deserialization.
func (v *Vendor) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	parsed, err := NewVendor(raw)
	if err != nil {
		return err
	}
	*v = parsed
	return nil
}

// MarshalJSON serializes the vendor as its string representation.
func (v Vendor) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}
