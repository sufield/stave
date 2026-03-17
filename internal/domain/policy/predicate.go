package policy

import "github.com/sufield/stave/internal/domain/asset"

// PredicateParser defines a function that can expand a raw value into a nested logic tree.
type PredicateParser func(v any) (*UnsafePredicate, error)

// UnsafePredicate defines the logical conditions required to classify a resource as unsafe.
type UnsafePredicate struct {
	// Any matches if at least one rule evaluates to true (Logical OR).
	Any []PredicateRule `yaml:"any,omitempty"`
	// All matches only if every rule evaluates to true (Logical AND).
	All []PredicateRule `yaml:"all,omitempty"`
}

// Evaluate performs a standalone evaluation against a specific asset.
func (p UnsafePredicate) Evaluate(a asset.Asset, params ControlParams) bool {
	return p.EvaluateWithContext(NewAssetEvalContext(a, params))
}

// EvaluateIdentity performs a standalone evaluation against a cloud identity (e.g. Service Account).
func (p UnsafePredicate) EvaluateIdentity(id asset.CloudIdentity, params ControlParams) bool {
	return p.EvaluateWithContext(NewIdentityEvalContext(id, params))
}

// EvaluateWithContext executes the predicate logic against a prepared evaluation context.
func (p UnsafePredicate) EvaluateWithContext(ctx EvalContext) bool {
	// 1. Evaluate "Any" (OR logic)
	// If any rule matches, the entire predicate is satisfied immediately.
	for i := range p.Any {
		if p.Any[i].MatchesWithContext(ctx) {
			return true
		}
	}

	// 2. Evaluate "All" (AND logic)
	// If the "All" block exists, all rules within it must satisfy.
	if len(p.All) > 0 {
		for i := range p.All {
			if !p.All[i].MatchesWithContext(ctx) {
				return false
			}
		}
		return true
	}

	return false
}

// EvalContext encapsulates all state available to a predicate during evaluation.
type EvalContext struct {
	Properties      map[string]any        // Resource-bound properties
	CloudIdentity   *asset.CloudIdentity  // The specific identity being checked
	Identities      []asset.CloudIdentity // Global identities (e.g. for any_match checks)
	Params          ControlParams         // Control-specific configuration
	PredicateParser PredicateParser       // Logic for parsing nested predicates
}

// Param retrieves a value from the control's parameter block.
func (ctx EvalContext) Param(key string) (any, bool) {
	return ctx.Params.Get(key)
}

// ParsePredicate attempts to expand a raw value into a nested predicate.
func (ctx EvalContext) ParsePredicate(v any) (*UnsafePredicate, error) {
	if ctx.PredicateParser == nil {
		return nil, nil
	}
	return ctx.PredicateParser(v)
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

// NewIdentityEvalContext builds a context focused on a specific identity's attributes.
func NewIdentityEvalContext(id asset.CloudIdentity, params ControlParams) EvalContext {
	return EvalContext{
		CloudIdentity: &id,
		Params:        params,
	}
}
