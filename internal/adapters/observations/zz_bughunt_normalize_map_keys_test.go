package observations

import (
	"testing"
)

func TestBugHunt_NormalizeValue_NonStringMapKeys(t *testing.T) {
	// A map with integer keys
	inputMap := map[int]any{
		100: "value-1",
		200: "value-2",
	}

	normalized := normalizeValue(inputMap)
	m, ok := normalized.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T (%v)", normalized, normalized)
	}

	// Under the buggy code: keys are converted to "<int Value>" resulting in collision
	// and only one key remaining.
	if len(m) != 2 {
		t.Fatalf("expected map of size 2, got %d", len(m))
	}

	if m["100"] != "value-1" {
		t.Errorf("expected m[\"100\"] to be \"value-1\", got %v", m["100"])
	}
	if m["200"] != "value-2" {
		t.Errorf("expected m[\"200\"] to be \"value-2\", got %v", m["200"])
	}
}
