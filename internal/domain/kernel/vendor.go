package kernel

import (
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
