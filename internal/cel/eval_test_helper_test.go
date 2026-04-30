package cel

import "fmt"

// evaluateWithParams is a test-only helper that runs a compiled CEL predicate
// with raw property maps. Production code uses Evaluate(asset.Asset) instead.
func evaluateWithParams(cp CompiledPredicate, props map[string]any, params map[string]any, identities []any) (bool, error) {
	if params == nil {
		params = map[string]any{}
	}
	if identities == nil {
		identities = []any{}
	}

	// Mirror production Evaluate(): the `identity` slot is the first
	// element of `identities` so single-identity controls work the
	// same way in tests as they do in production. Hardcoding it to
	// {} (the previous shape) hid the real production bug Phase 7
	// fixed — single-identity-control predicates evaluated against
	// an empty map and silently never matched.
	identity := map[string]any{}
	if len(identities) > 0 {
		if first, ok := identities[0].(map[string]any); ok {
			identity = first
		}
	}

	activation := map[string]any{
		"properties": props,
		"params":     params,
		"identities": identities,
		"identity":   identity,
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
