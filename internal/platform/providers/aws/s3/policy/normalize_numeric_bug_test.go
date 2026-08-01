package policy

import (
	"testing"
)

func TestNormalizeStringOrSlice_PreservesNumericValues(t *testing.T) {
	// Numeric account ID in single value
	gotSingle := NormalizeStringOrSlice(123456789012)
	if len(gotSingle) != 1 || gotSingle[0] != "123456789012" {
		t.Errorf("expected [\"123456789012\"] for numeric input, got %v", gotSingle)
	}

	// Slice of numeric values (e.g. account IDs / ports)
	gotSlice := NormalizeStringOrSlice([]any{123456789012, 987654321098})
	if len(gotSlice) != 2 || gotSlice[0] != "123456789012" || gotSlice[1] != "987654321098" {
		t.Errorf("expected [\"123456789012\", \"987654321098\"] for []any numeric input, got %v", gotSlice)
	}
}
