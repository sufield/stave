// predicate.go implements UnsafePredicate evaluation logic.
package policy

import "github.com/sufield/stave/internal/domain/asset"

// UnsafePredicate defines the conditions for a resource/identity to be considered unsafe.
type UnsafePredicate struct {
	Any []PredicateRule `yaml:"any,omitempty"`
	All []PredicateRule `yaml:"all,omitempty"`
}

// Evaluate checks if the predicate matches the given resource.
func (p *UnsafePredicate) Evaluate(r asset.Asset, params ControlParams) bool {
	return p.EvaluateWithContext(NewResourceEvalContext(r, params))
}

// EvaluateIdentity checks if the predicate matches the given identity.
func (p *UnsafePredicate) EvaluateIdentity(id asset.CloudIdentity, params ControlParams) bool {
	return p.EvaluateWithContext(NewIdentityEvalContext(id, params))
}

// EvalContext provides context for predicate evaluation.
type EvalContext struct {
	Properties      map[string]any                        // resource properties
	CloudIdentity   *asset.CloudIdentity                  // identity being evaluated (nil for resources)
	Identities      []asset.CloudIdentity                 // all snapshot identities for any_match
	Params          ControlParams                         // control params for value_from_param
	PredicateParser func(v any) (*UnsafePredicate, error) // nested predicate parser for any_match
}

// NewResourceEvalContext creates a context for evaluating a resource.
func NewResourceEvalContext(r asset.Asset, params ControlParams) EvalContext {
	return EvalContext{
		Properties: r.Properties,
		Params:     params,
	}
}

// NewResourceEvalContextWithIdentities creates a resource eval context that
// includes snapshot-level identities for any_match predicates.
func NewResourceEvalContextWithIdentities(r asset.Asset, params ControlParams, identities []asset.CloudIdentity) EvalContext {
	return EvalContext{
		Properties: r.Properties,
		Params:     params,
		Identities: identities,
	}
}

// NewIdentityEvalContext creates a context for evaluating an identity.
func NewIdentityEvalContext(id asset.CloudIdentity, params ControlParams) EvalContext {
	return EvalContext{
		CloudIdentity: &id,
		Params:        params,
	}
}

// EvaluateWithContext evaluates predicates with full context.
func (p *UnsafePredicate) EvaluateWithContext(ctx EvalContext) bool {
	hasAny := len(p.Any) > 0
	hasAll := len(p.All) > 0

	// 1) Check "any" rules (short-circuit OR logic).
	// If any rule matches, the predicate is true regardless of "all" rules.
	if hasAny {
		for i := range p.Any {
			if p.Any[i].MatchesWithContext(ctx) {
				return true
			}
		}
		// If "any" was specified but none matched and no "all" rules exist, fail.
		if !hasAll {
			return false
		}
	}

	// 2) Check "all" rules (short-circuit AND logic).
	if hasAll {
		for i := range p.All {
			if !p.All[i].MatchesWithContext(ctx) {
				return false
			}
		}
		return true
	}

	return false
}
