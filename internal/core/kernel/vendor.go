package kernel

import (
	"encoding/json"
	"errors"
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
	v := Vendor(toLowerTrim(raw))
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

// AppliesToVendor reports whether a control with the given scope tags
// applies to an asset of the given vendor.
//
// Heuristic:
//   - A control with no scope tags is universal — applies to every
//     vendor (returns true).
//   - A scope tag is treated as a vendor identifier when it is short
//     (≤10 characters). Vendor identifiers in the catalog look like
//     "aws", "gcp", "azure", "kubernetes" — never longer.
//   - Longer tags are domain or feature tags ("apigateway",
//     "supply-chain", "kubernetes-runtime") and are ignored by this
//     check.
//   - If at least one vendor-shaped tag (≤10 chars) is present and
//     none equals the asset's vendor, the control does NOT apply.
//   - If no vendor-shaped tag is present at all, the control is
//     treated as universal — same as having no scope tags.
//
// This is the single source of truth for vendor applicability.
// Both the engine pipeline (engine/lifecycles.go) and the risk
// pipeline (risk/upcoming.go) call it so the two pipelines cannot
// drift on the heuristic.
//
// An empty vendor never matches a vendor-shaped tag and falls
// through to the universal-or-none branch — empty vendor against
// no vendor tags returns true (universal); empty vendor against
// any vendor tag returns false (no match).
func AppliesToVendor(scopeTags []ScopeTag, vendor Vendor) bool {
	if len(scopeTags) == 0 {
		return true
	}
	hasVendorTag := false
	for _, tag := range scopeTags {
		// "multicloud" signals a cross-provider control — treat as universal.
		if tag == "multicloud" {
			return true
		}
		if !isVendorTag(tag) {
			continue
		}
		hasVendorTag = true
		if Vendor(tag) == vendor {
			return true
		}
	}
	return !hasVendorTag
}

// isVendorTag reports whether a scope tag is plausibly a vendor name.
// Vendor names in this project are short ASCII strings ("aws", "gcp",
// "azure", "k8s", "github", "dns") — at most 10 characters. Tags longer
// than that are domain or capability classifiers that AppliesToVendor
// must skip rather than treat as vendor mismatches.
//
// The 10-char threshold is calibrated on the existing vendor catalog;
// extend ScopeTag with a richer kind discriminator if a longer vendor
// name lands.
func isVendorTag(tag ScopeTag) bool {
	return len(tag) <= 10
}
