package cel

import (
	"testing"
)

// TestStringifyNamedTypes_NilMapPreservedAsNil verifies that stringifyNamedTypes
// preserves nil maps as nil instead of converting them into empty non-nil maps.
// Converting nil map to map[string]any{} causes CEL's has(...) operator to return true
// and `== null` to return false on absent/null map properties.
func TestStringifyNamedTypes_NilMapPreservedAsNil(t *testing.T) {
	t.Parallel()

	var nilMap map[string]any = nil
	res := stringifyNamedTypes(nilMap)
	if res != nil {
		t.Fatalf("CRITICAL BUG: stringifyNamedTypes(nil) returned non-nil map %v (%T); expected nil", res, res)
	}
}
