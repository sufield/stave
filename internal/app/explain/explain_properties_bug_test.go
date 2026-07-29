package explain

import (
	"testing"

	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestBuildMinimalObservation_NoNestedPropertiesKey(t *testing.T) {
	fields := []string{"properties"}
	rules := []contracts.ExplainRule{
		{Path: "properties", Op: predicate.OpPresent, Value: "example"},
	}

	obs := buildMinimalObservation(fields, rules)
	assets, ok := obs["assets"].([]map[string]any)
	if !ok || len(assets) == 0 {
		t.Fatalf("expected non-empty assets slice")
	}

	props, ok := assets[0]["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected properties map on asset")
	}

	// Setting "properties" field should not create a nested map props["properties"]
	if _, exists := props["properties"]; exists {
		t.Errorf("properties map contained unwanted nested 'properties' key: %v", props)
	}
}
