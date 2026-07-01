package observations

import (
	"testing"
)

func TestBugHunt_NormalizeProperties_TypedNil(t *testing.T) {
	// A map containing a typed nil slice and a typed nil map.
	// Since Go interface values containing typed nil values are not strictly equal to nil,
	// they bypass the `v == nil` check. In the original code, the reflection fallback
	// converts them into non-nil empty slices/maps, changing the data shape.
	var nilSlice []int
	var nilMap map[string]int

	m := map[string]any{
		"slice": nilSlice,
		"map":   nilMap,
	}

	normalizeProperties(m)

	if m["slice"] != nil {
		t.Errorf("slice was normalized to %T (%v), want nil", m["slice"], m["slice"])
	}
	if m["map"] != nil {
		t.Errorf("map was normalized to %T (%v), want nil", m["map"], m["map"])
	}
}
