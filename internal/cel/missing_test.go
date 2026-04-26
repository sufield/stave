package cel

import (
	"testing"

	"github.com/google/cel-go/common/types"
)

func TestIsMissing_KeyNotFound(t *testing.T) {
	val := types.NewErr("no such key: public_access_block")
	if !isMissing(val) {
		t.Error("isMissing should return true for key-not-found (structural missing)")
	}
}

func TestIsMissing_UndefinedField(t *testing.T) {
	val := types.NewErr("undefined field 'nonexistent'")
	if !isMissing(val) {
		t.Error("isMissing should return true for undefined field (structural missing)")
	}
}

func TestIsMissing_NullValue(t *testing.T) {
	if !isMissing(types.NullValue) {
		t.Error("isMissing should return true for null values")
	}
}

func TestIsMissing_Nil(t *testing.T) {
	if !isMissing(nil) {
		t.Error("isMissing should return true for nil")
	}
}

func TestIsMissing_DivisionByZero_NotMissing(t *testing.T) {
	val := types.NewErr("division by zero")
	if isMissing(val) {
		t.Error("BUG: isMissing returns true for division-by-zero. " +
			"Runtime errors must propagate, not be treated as missing data.")
	}
}

func TestIsMissing_TypeMismatch_NotMissing(t *testing.T) {
	val := types.NewErr("type mismatch: expected string, got int")
	if isMissing(val) {
		t.Error("BUG: isMissing returns true for type-mismatch. " +
			"Broken predicates silently produce safe verdicts.")
	}
}

func TestIsMissing_OverloadFailure_NotMissing(t *testing.T) {
	val := types.NewErr("no such overload: size(int)")
	if isMissing(val) {
		t.Error("BUG: isMissing returns true for 'no such overload' — " +
			"overload-resolution failures are type errors (e.g. calling " +
			"size() on an int), not absence. They must surface as " +
			"inconclusive rather than be silently classified as missing.")
	}
	if !IsTypeError(val) {
		t.Error("IsTypeError should return true for 'no such overload'")
	}
}

func TestIsTypeError_NoMatchingOverload(t *testing.T) {
	val := types.NewErr("no matching overload for '_==_'")
	if !IsTypeError(val) {
		t.Error("IsTypeError should return true for 'no matching overload'")
	}
	if isMissing(val) {
		t.Error("type errors must not be classified as missing")
	}
}

func TestIsTypeError_StructuralMissing_False(t *testing.T) {
	val := types.NewErr("no such key: foo")
	if IsTypeError(val) {
		t.Error("IsTypeError must not flag structural-absence errors as type errors")
	}
}

func TestIsTypeError_NonError_False(t *testing.T) {
	if IsTypeError(types.String("ok")) {
		t.Error("IsTypeError must return false for non-error values")
	}
	if IsTypeError(nil) {
		t.Error("IsTypeError must return false for nil")
	}
}

func TestIsMissing_EmptyString_IsMissing(t *testing.T) {
	if !isMissing(types.String("")) {
		t.Error("isMissing should return true for empty string")
	}
}

func TestIsMissing_NonEmptyString_NotMissing(t *testing.T) {
	if isMissing(types.String("value")) {
		t.Error("isMissing should return false for non-empty string")
	}
}
