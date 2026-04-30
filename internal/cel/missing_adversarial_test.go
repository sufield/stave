package cel

import (
	"testing"

	"github.com/google/cel-go/common/types"
)

// TestIsMissing_FalseBoolean_IsNotMissing is the most critical
// adversarial test. If isMissing returns true for boolean false,
// every control of the form "encryption.enabled == true" silently
// passes when encryption is disabled (false).
func TestIsMissing_FalseBoolean_IsNotMissing(t *testing.T) {
	t.Parallel()
	if isMissing(types.Bool(false)) {
		t.Error(
			"CRITICAL BUG: isMissing returns true for boolean false. " +
				"Controls like 'encryption.enabled == true' silently pass " +
				"when encryption is disabled.")
	}
}

// TestIsMissing_ZeroInt_IsNotMissing verifies that integer zero is
// not treated as missing. Zero is a valid configuration value
// (e.g., lockout_threshold=0 means no lockout — should be detectable).
func TestIsMissing_ZeroInt_IsNotMissing(t *testing.T) {
	t.Parallel()
	if isMissing(types.Int(0)) {
		t.Error(
			"BUG: isMissing returns true for integer 0. " +
				"Zero is a valid value — lockout_threshold=0 should be detectable.")
	}
}

// TestIsMissing_EmptyString_IsMissingByDesign documents that empty
// string IS treated as missing by design. The missing() operator
// treats absent-or-empty as the same concept. This is intentional —
// op:missing checks "is this field absent, null, or empty?"
//
// Controls that need to distinguish "present but empty" from "absent"
// use op:eq with value "" instead of op:missing.
func TestIsMissing_EmptyString_IsMissingByDesign(t *testing.T) {
	t.Parallel()
	result := isMissing(types.String(""))
	if !result {
		t.Error("empty string should be treated as missing by the missing() operator")
	}
	// This is by design: op:missing means "absent or empty"
	t.Log("empty string → missing=true (by design: op:missing treats absent/empty the same)")
}

// TestIsMissing_WhitespaceOnlyString_IsMissing verifies that
// whitespace-only strings are treated as missing (trimmed to empty).
func TestIsMissing_WhitespaceOnlyString_IsMissing(t *testing.T) {
	t.Parallel()
	if !isMissing(types.String("   ")) {
		t.Error("whitespace-only string should be treated as missing")
	}
}

// TestIsMissing_TrueBool_IsNotMissing verifies boolean true is not missing.
func TestIsMissing_TrueBool_IsNotMissing(t *testing.T) {
	t.Parallel()
	if isMissing(types.Bool(true)) {
		t.Error("boolean true should not be missing")
	}
}

// TestIsMissing_PositiveInt_IsNotMissing verifies positive integers are not missing.
func TestIsMissing_PositiveInt_IsNotMissing(t *testing.T) {
	t.Parallel()
	if isMissing(types.Int(42)) {
		t.Error("positive integer should not be missing")
	}
}

// TestIsMissing_Float_IsNotMissing verifies float values are not missing.
func TestIsMissing_Float_IsNotMissing(t *testing.T) {
	t.Parallel()
	if isMissing(types.Double(3.14)) {
		t.Error("float value should not be missing")
	}
}
