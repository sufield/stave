package cel

import (
	"reflect"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestBugHunt_StringifyValue_Pointer(t *testing.T) {
	t.Parallel()

	// Test pointer to string
	strVal := "hello"
	gotStr := stringifyValue(&strVal)
	if !reflect.DeepEqual(gotStr, "hello") {
		t.Errorf("expected stringifyValue(&string) to be 'hello', got %v (%T)", gotStr, gotStr)
	}

	// Test pointer to int
	intVal := 42
	gotInt := stringifyValue(&intVal)
	if !reflect.DeepEqual(gotInt, 42) {
		t.Errorf("expected stringifyValue(&int) to be 42, got %v (%T)", gotInt, gotInt)
	}

	// Test pointer to bool
	boolVal := true
	gotBool := stringifyValue(&boolVal)
	if !reflect.DeepEqual(gotBool, true) {
		t.Errorf("expected stringifyValue(&bool) to be true, got %v (%T)", gotBool, gotBool)
	}

	// Test nested pointer in map
	nested := map[string]any{
		"ptr_key": &strVal,
	}
	gotMap := stringifyValue(nested)
	gotMapTyped, ok := gotMap.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", gotMap)
	}
	if gotMapTyped["ptr_key"] != "hello" {
		t.Errorf("expected map key to be resolved to 'hello', got %v (%T)", gotMapTyped["ptr_key"], gotMapTyped["ptr_key"])
	}
}

func TestBugHunt_Evaluate_WithPointerProperty(t *testing.T) {
	t.Parallel()

	compiler, err := NewCompiler()
	if err != nil {
		t.Fatalf("failed to create compiler: %v", err)
	}

	pred := policy.UnsafePredicate{
		All: []policy.PredicateRule{
			{
				Field: predicate.NewFieldPath("properties.bucket_name"),
				Op:    predicate.OpEq,
				Value: policy.Str("my-bucket"),
			},
		},
	}

	cp, err := compiler.Compile(pred)
	if err != nil {
		t.Fatalf("failed to compile predicate: %v", err)
	}

	bucketName := "my-bucket"
	a := asset.Asset{
		Properties: map[string]any{
			"bucket_name": &bucketName,
		},
	}

	matched, err := Evaluate(cp, a, nil, nil)
	if err != nil {
		t.Fatalf("failed to evaluate predicate: %v", err)
	}

	if !matched {
		t.Error("expected predicate to match when using pointer property")
	}
}
