package cel

import (
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
)

func TestBugHunt_StringifyValue_TypedMap(t *testing.T) {
	t.Parallel()

	// A property map might contain typed maps, e.g. map[string]string or map[string]kernel.AssetType.
	// In the original code, map types other than map[string]any fell through to the default reflect path,
	// which did not handle reflect.Map, returning the map as-is. This meant any custom string types
	// nested inside (e.g. kernel.AssetType) were NOT stringified before reaching CEL, breaking comparisons.
	input := map[string]kernel.AssetType{
		"my-bucket": "aws_s3_bucket",
	}

	got := stringifyValue(input)

	// We expect got to be a map[string]any where all values are stringified to plain strings.
	gotMap, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T (%v)", got, got)
	}

	val, ok := gotMap["my-bucket"]
	if !ok {
		t.Fatal("expected key 'my-bucket' in returned map")
	}

	if _, isPlainString := val.(string); !isPlainString {
		t.Errorf("expected stringified value to be plain string, got %T (%v)", val, val)
	}
}
