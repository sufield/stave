package cel

import (
	"fmt"
	"reflect"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
)

// Evaluate runs a compiled CEL predicate against asset properties.
// Returns true if the asset matches the unsafe predicate (i.e., is unsafe).
func Evaluate(cp CompiledPredicate, a asset.Asset, identities []asset.CloudIdentity) (bool, error) {
	props := stringifyNamedTypes(a.Map())

	// Build identity list as []map[string]any for CEL
	idList := make([]any, len(identities))
	for i, id := range identities {
		idList[i] = stringifyNamedTypes(id.Map())
	}

	activation := map[string]any{
		"properties": props,
		"params":     map[string]any{},
		"identities": idList,
		"identity":   map[string]any{},
	}

	out, _, err := cp.Program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("CEL eval: %w\n  expression: %s", err, cp.Expression)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL eval: expected bool, got %T", out.Value())
	}
	return result, nil
}

// stringifyNamedTypes recursively converts named string types (like
// kernel.AssetType, kernel.Vendor, asset.ID) to plain strings so CEL's
// == operator can compare them with string literals.
func stringifyNamedTypes(m map[string]any) map[string]any {
	for k, v := range m {
		m[k] = stringifyValue(v)
	}
	return m
}

func stringifyValue(v any) any {
	if v == nil {
		return v
	}
	switch val := v.(type) {
	case string:
		return val
	case bool, float64, int, int64, float32:
		return val
	case map[string]any:
		return stringifyNamedTypes(val)
	case []any:
		for i, elem := range val {
			val[i] = stringifyValue(elem)
		}
		return val
	default:
		rv := reflect.ValueOf(v)
		if rv.Kind() == reflect.String {
			return rv.String()
		}
		return v
	}
}

// EvaluateWithParams runs a compiled CEL predicate with control parameters.
func EvaluateWithParams(cp CompiledPredicate, props map[string]any, params map[string]any, identities []any) (bool, error) {
	if params == nil {
		params = map[string]any{}
	}
	if identities == nil {
		identities = []any{}
	}

	activation := map[string]any{
		"properties": props,
		"params":     params,
		"identities": identities,
		"identity":   map[string]any{},
	}

	out, _, err := cp.Program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("CEL eval: %w", err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL eval: expected bool, got %T", out.Value())
	}
	return result, nil
}
