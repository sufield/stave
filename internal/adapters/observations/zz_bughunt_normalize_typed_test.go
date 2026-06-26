package observations

import (
	"testing"
)

func TestBugHunt_NormalizeProperties_TypedSlicesAndMaps(t *testing.T) {
	m := map[string]any{
		"typed_slice": []string{"true", "false", "value"},
		"typed_map":   map[string]string{"enabled": "true", "name": "test"},
		"slice_of_maps": []map[string]any{
			{"flag": "true"},
		},
	}
	normalizeProperties(m)

	// Assertions:
	// "typed_slice" should become []any{true, false, "value"}
	sliceVal, ok := m["typed_slice"].([]any)
	if !ok {
		t.Fatalf("expected typed_slice to be coerced to []any, got %T", m["typed_slice"])
	}
	if sliceVal[0] != true || sliceVal[1] != false || sliceVal[2] != "value" {
		t.Errorf("unexpected coerced slice values: %v", sliceVal)
	}

	// "typed_map" should become map[string]any{"enabled": true, "name": "test"}
	mapVal, ok := m["typed_map"].(map[string]any)
	if !ok {
		t.Fatalf("expected typed_map to be coerced to map[string]any, got %T", m["typed_map"])
	}
	if mapVal["enabled"] != true || mapVal["name"] != "test" {
		t.Errorf("unexpected coerced map values: %v", mapVal)
	}

	// "slice_of_maps" should become []any{map[string]any{"flag": true}}
	someSlice, ok := m["slice_of_maps"].([]any)
	if !ok {
		t.Fatalf("expected slice_of_maps to be coerced to []any, got %T", m["slice_of_maps"])
	}
	firstMap, ok := someSlice[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first element of slice_of_maps to be map[string]any, got %T", someSlice[0])
	}
	if firstMap["flag"] != true {
		t.Errorf("expected flag to be true, got %v", firstMap["flag"])
	}
}
