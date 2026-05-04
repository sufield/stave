package cel

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/google/cel-go/common/types/ref"

	"github.com/sufield/stave/internal/core/asset"
)

// isUnresolved reports whether a CEL evaluation result represents
// a null/unresolved value — typically the symptom of an expression
// that walked through a missing field without a `has(...)` guard.
// Centralises the nil-check so callers describe the *outcome*
// ("the predicate did not resolve") instead of the implementation
// detail (`out.Value() == nil`); a future cel-go version that
// represents null with a typed sentinel rather than a Go nil
// changes one site, not every consumer.
func isUnresolved(v ref.Val) bool {
	return v == nil || v.Value() == nil
}

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

	activation := NewActivation(props, params, idList)

	out, _, err := cp.program.Eval(map[string]any(activation))
	if err != nil {
		return false, fmt.Errorf("cel eval: %w\n  expression: %s", err, cp.Expression)
	}

	if isUnresolved(out) {
		// Surface explicitly because a null resolution is usually a
		// logic error in the expression (e.g. missing has() guard
		// before walking through an absent field). The generic
		// "expected bool, got <nil>" path is harder to triage than
		// "predicate returned null".
		return false, errors.New("cel eval: predicate returned null instead of bool")
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
		case reflect.Struct, reflect.Pointer, reflect.Interface:
			// Producer leaks: a custom struct (or pointer/interface
			// wrapping one) escaped into the activation map. CEL
			// cannot dereference fields on Go structs and the
			// previous pass-through silently let the value reach
			// the evaluator as `dyn` — predicates against it
			// returned undefined-behaviour results that varied
			// across cel-go releases. Render to a stringified
			// fingerprint with %+v so the value appears in CEL as
			// a comparable scalar; predicates that depend on
			// internal struct fields will visibly fail to match
			// rather than evaluating against a phantom value.
			return fmt.Sprintf("%+v", v)
		default:
			return v
		}
	}
}
