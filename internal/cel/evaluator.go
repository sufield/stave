package cel

import (
	"fmt"

	"github.com/sufield/stave/internal/domain/asset"
)

// Evaluate runs a compiled CEL predicate against asset properties.
// Returns true if the asset matches the unsafe predicate (i.e., is unsafe).
func Evaluate(cp CompiledPredicate, a asset.Asset, identities []asset.CloudIdentity) (bool, error) {
	props := a.Map()

	// Build identity list as []map[string]any for CEL
	idList := make([]any, len(identities))
	for i, id := range identities {
		idList[i] = id.Map()
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
