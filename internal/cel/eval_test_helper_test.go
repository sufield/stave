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
