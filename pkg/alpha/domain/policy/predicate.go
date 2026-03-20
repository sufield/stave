package policy

import "github.com/sufield/stave/pkg/alpha/domain/asset"

// PredicateParser defines a function that can expand a raw value into a nested logic tree.
type PredicateParser func(v any) (*UnsafePredicate, error)

// UnsafePredicate defines the logical conditions required to classify a resource as unsafe.
type UnsafePredicate struct {
	// Any matches if at least one rule evaluates to true (Logical OR).
	Any []PredicateRule
	// All matches only if every rule evaluates to true (Logical AND).
	All []PredicateRule
}

// PredicateEval evaluates whether an asset is unsafe according to a control's
// predicate. This function type decouples evaluation consumers from the
// evaluation engine implementation (CEL or built-in).
type PredicateEval func(ctl ControlDefinition, a asset.Asset, identities []asset.CloudIdentity) (unsafe bool, err error)

// EvalContext encapsulates all state available to a predicate during evaluation.
type EvalContext struct {
	Properties      map[string]any        // Resource-bound properties
	CloudIdentity   *asset.CloudIdentity  // The specific identity being checked
	Identities      []asset.CloudIdentity // Global identities (e.g. for any_match checks)
	Params          ControlParams         // Control-specific configuration
	PredicateParser PredicateParser       // Logic for parsing nested predicates
}

// --- Constructors ---

// NewAssetEvalContext builds a context focused on resource properties.
func NewAssetEvalContext(a asset.Asset, params ControlParams, identities ...asset.CloudIdentity) EvalContext {
	return EvalContext{
		Properties: a.Map(),
		Params:     params,
		Identities: identities,
	}
}
