package cel

import (
	"fmt"
	"reflect"

	"github.com/sufield/stave/internal/core/asset"
)

// Evaluate runs a compiled CEL predicate against asset properties.
// Returns true if the asset matches the unsafe predicate (i.e., is unsafe).
// params are the control's configured parameters (e.g., min_retention_days).
func Evaluate(cp CompiledPredicate, a asset.Asset, identities []asset.CloudIdentity, params map[string]any) (bool, error) {
	if cp.program == nil {
		// Reach the caller with the source expression (when present)
		// so the operator can correlate the failure back to the
		// control YAML even though compilation never succeeded.
		expr := cp.Expression
		if expr == "" {
			expr = "<empty>"
		}
		return false, fmt.Errorf("cel eval: predicate has no compiled program (expression: %s)", expr)
	}
	props := stringifyNamedTypes(a.Map())

	// Build identity list as []map[string]any for CEL
	idList := make([]any, len(identities))
	for i, id := range identities {
		idList[i] = stringifyNamedTypes(id.Map())
	}

	if params == nil {
		params = map[string]any{}
	}

	// `identity` is the convenience accessor for the *first* identity
	// when a control wants to talk about "the" identity attached to an
	// asset (single-principal resources, IAM-bound services).
	// Multi-identity controls iterate `identities` instead. Hardcoding
	// an empty map silently masked all per-identity field reads in
	// single-identity controls — predicates like
	// `identity.type == "service_role"` evaluated against `{}`,
	// returning false on every asset regardless of input.
	identity := map[string]any{}
	if len(idList) > 0 {
		if first, ok := idList[0].(map[string]any); ok {
			identity = first
		}
	}
	activation := map[string]any{
		"properties": props,
		"params":     params,
		"identities": idList,
		"identity":   identity,
	}

	out, _, err := cp.program.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("cel eval: %w\n  expression: %s", err, cp.Expression)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("cel eval: expected bool, got %T", out.Value())
	}
	return result, nil
}

// stringifyNamedTypes recursively converts named string types (like
// kernel.AssetType, kernel.Vendor, asset.ID) to plain strings so CEL's
// == operator can compare them with string literals.
// Returns a new map — does not mutate the input.
func stringifyNamedTypes(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = stringifyValue(v)
	}
	return out
}

func stringifyValue(v any) any {
	if v == nil {
		return v
	}
	switch val := v.(type) {
	case string:
		return val
	// Cover the integer / float widths that observation extractors
	// realistically produce. The narrower extractors (json.Number
	// numeric, manual int casts in adapters) need the int32 / uint /
	// uint64 / uint32 cases to pass through without falling into the
	// reflect path, which loses signedness on uint64.
	case bool, float64, float32, int, int32, int64, uint, uint32, uint64:
		return val
	case map[string]any:
		return stringifyNamedTypes(val) // returns new map, no mutation
	case []any:
		cp := make([]any, len(val))
		for i, elem := range val {
			cp[i] = stringifyValue(elem)
		}
		return cp
	default:
		rv := reflect.ValueOf(v)
		switch rv.Kind() {
		case reflect.String:
			return rv.String()
		case reflect.Slice, reflect.Array:
			// Concrete typed slices like []map[string]any or
			// []asset.CloudIdentity do not match `case []any` above,
			// but we still need to walk their elements so any
			// named-string types nested inside (e.g. asset.ID,
			// kernel.AssetType) are converted before CEL sees them.
			n := rv.Len()
			cp := make([]any, n)
			for i := range n {
				cp[i] = stringifyValue(rv.Index(i).Interface())
			}
			return cp
		default:
			return v
		}
	}
}
