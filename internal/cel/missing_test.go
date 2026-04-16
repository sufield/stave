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

func TestIsMissing_InvalidFunctionCall_NotMissing(t *testing.T) {
	val := types.NewErr("no such overload: size(int)")
	if isMissing(val) {
		t.Error("BUG: isMissing returns true for invalid function call. " +
			"Calling size() on wrong type silently passes.")
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
