package kernel

import (
	"fmt"
	"strings"
)

// Vendor represents the cloud vendor that owns a resource (e.g., "aws").
type Vendor string

const (
	// VendorAWS represents Amazon Web Services.
	VendorAWS Vendor = "aws"
)

// String implements fmt.Stringer.
func (v Vendor) String() string {
	return string(v)
}

// ParseVendor validates and normalizes a vendor value.
// Any non-empty string is accepted; the value is lowercased and trimmed.
func ParseVendor(s string) (Vendor, error) {
	v := Vendor(strings.ToLower(strings.TrimSpace(s)))
	if v == "" {
		return "", fmt.Errorf("vendor name cannot be empty")
	}
	return v, nil
}
