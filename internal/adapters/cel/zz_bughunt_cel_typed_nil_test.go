package cel

import (
	"testing"
)

func TestBugHunt_StringifyValue_TypedNil(t *testing.T) {
	t.Parallel()

	// A typed nil slice and map.
	// In the original code, the reflection fallback in stringifyValue
	// converts them into non-nil empty slices/maps, changing the data shape.
	var nilSlice []int
	var nilMap map[string]int

	gotSlice := stringifyValue(nilSlice)
	if gotSlice != nil {
		t.Errorf("expected stringifyValue(nilSlice) to be nil, got %v (%T)", gotSlice, gotSlice)
	}

	gotMap := stringifyValue(nilMap)
	if gotMap != nil {
		t.Errorf("expected stringifyValue(nilMap) to be nil, got %v (%T)", gotMap, gotMap)
	}
}
