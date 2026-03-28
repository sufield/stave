package controldef

import "github.com/sufield/stave/internal/core/asset"

// PredicateParser defines a function that can expand a raw value into a nested logic tree.
type PredicateParser func(v any) (*UnsafePredicate, error)

// UnsafePredicate defines the logical conditions required to classify a resource as unsafe.
type UnsafePredicate struct {
	// Any matches if at least one rule evaluates to true (Logical OR).
	Any []PredicateRule `json:"any,omitempty"`
	// All matches only if every rule evaluates to true (Logical AND).
	All []PredicateRule `json:"all,omitempty"`
}

// PredicateEval evaluates whether an asset is unsafe according to a control's
// predicate. This function type decouples evaluation consumers from the
// evaluation engine implementation (CEL or built-in).
type PredicateEval func(ctl ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (unsafe bool, err error)

// EvalContext encapsulates all state available to a predicate during evaluation.
type EvalContext struct {
	Properties      map[string]any
	CloudIdentity   *asset.CloudIdentity
	Identities      []asset.CloudIdentity
	Params          ControlParams
	PredicateParser PredicateParser
}

// NewAssetEvalContext builds a context focused on resource properties.
func NewAssetEvalContext(a asset.Asset, params ControlParams, parser PredicateParser, identities ...asset.CloudIdentity) *EvalContext {
	ids := make([]asset.CloudIdentity, len(identities))
	copy(ids, identities)

	return &EvalContext{
		Properties:      a.Map(),
		Params:          params,
		Identities:      ids,
		PredicateParser: parser,
	}
}
