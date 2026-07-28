package kernel

import (
	"slices"
	"strings"
)

// ControlClass categorizes the high-level security intent of a control.
type ControlClass int

// High-level security intent classifications for controls.
const (
	ClassUnknown           ControlClass = iota
	ClassPublicExposure                 // Connectivity and exposure risks
	ClassEncryptionMissing              // Data-at-rest protection risks
	ClassBaselineViolation              // General configuration drift
)

// String implements the fmt.Stringer interface for logging and debugging.
func (c ControlClass) String() string {
	switch c {
	case ClassPublicExposure:
		return "public_exposure"
	case ClassEncryptionMissing:
		return "encryption_missing"
	case ClassBaselineViolation:
		return "baseline_violation"
	default:
		return "unknown"
	}
}

// Classify determines the security class of a ControlID based on its path segments.
//
// It expects a dot-separated ID format (e.g., "CTL.SERVICE.CATEGORY.ID").
// By looking for keywords rather than vendor names, the kernel remains agnostic.
func (id ControlID) Classify() ControlClass {
	s := strings.ToUpper(id.String())

	// Check for Public Exposure keywords (middle segment or trailing segment)
	if containsAny(s, ".PUBLIC.", ".EXPOSURE.", ".TAKEOVER.", ".POLICY.WRITE") ||
		hasAnySuffix(s, ".PUBLIC", ".EXPOSURE", ".TAKEOVER", ".POLICY.WRITE") {
		return ClassPublicExposure
	}

	// Check for Encryption keywords (middle segment or trailing segment)
	if containsAny(s, ".ENCRYPT.", ".KMS.", ".SSE.") ||
		hasAnySuffix(s, ".ENCRYPT", ".KMS", ".SSE") {
		return ClassEncryptionMissing
	}

	// Default to baseline violation if it follows the Control prefix
	if strings.HasPrefix(s, "CTL.") {
		return ClassBaselineViolation
	}

	return ClassUnknown
}

func hasAnySuffix(s string, suffixes ...string) bool {
	return slices.ContainsFunc(suffixes, func(sub string) bool {
		return strings.HasSuffix(s, sub)
	})
}

// containsAny is a helper to check if any of the provided substrings exist in s.
func containsAny(s string, substrings ...string) bool {
	return slices.ContainsFunc(substrings, func(sub string) bool {
		return strings.Contains(s, sub)
	})
}
