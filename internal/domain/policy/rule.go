package policy

import (
	"cmp"
	"slices"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/predicate"
)

// PredicateRule represents a single logical gate in a security policy.
// It can be a simple field comparison or a nested "any/all" block.
type PredicateRule struct {
	// Simple field comparison
	Field          predicate.FieldPath
	Op             predicate.Operator
	Value          Operand
	ValueFromParam predicate.ParamRef

	// Nested logic blocks
	Any []PredicateRule
	All []PredicateRule
}

// Matches evaluates the rule against an asset without additional parameters or identities.
func (r *PredicateRule) Matches(a asset.Asset) bool {
	return r.MatchesWithContext(NewAssetEvalContext(a, ControlParams{}))
}

// MatchesWithContext evaluates the rule against a full evaluation context.
func (r *PredicateRule) MatchesWithContext(ctx EvalContext) bool {
	// 1. Handle Nested Logical Blocks (Recursive)
	if len(r.Any) > 0 {
		for i := range r.Any {
			if r.Any[i].MatchesWithContext(ctx) {
				return true
			}
		}
		return false
	}

	if len(r.All) > 0 {
		for i := range r.All {
			if !r.All[i].MatchesWithContext(ctx) {
				return false
			}
		}
		return true
	}

	// 2. Resolve Field Value
	val, exists := getFieldValueByParts(ctx, r.Field.Parts())

	// 3. Resolve Comparison Value (Literal or Parameter)
	compareVal := r.Value.Raw()
	if !r.ValueFromParam.IsZero() {
		paramVal, ok := ctx.Param(r.ValueFromParam.String())
		if !ok || paramVal == nil {
			return false // Parameter referenced but not provided
		}
		compareVal = paramVal
	}

	// 4. Evaluate Standard Operators
	if res, handled := predicate.EvaluateOperator(r.Op, exists, val, compareVal); handled {
		return res
	}

	// 5. Evaluate Complex/Contextual Operators
	return r.evaluateContextualOperator(ctx, exists, val, compareVal)
}

func (r *PredicateRule) evaluateContextualOperator(ctx EvalContext, exists bool, val, compareVal any) bool {
	if r.Op.RequiresNestedPredicate() {
		return evaluateAnyMatch(ctx, exists, val, compareVal)
	}

	if r.Op.IsFieldRef() {
		return r.evaluateFieldRef(ctx, exists, val, compareVal)
	}

	return false
}

func (r *PredicateRule) evaluateFieldRef(ctx EvalContext, exists bool, val, compareVal any) bool {
	otherPath, ok := compareVal.(string)
	if !ok {
		return false
	}
	otherVal, otherExists := GetFieldValueWithContext(ctx, otherPath)

	switch r.Op {
	case predicate.OpNotSubsetOfField:
		if !exists {
			return false
		}
		if !otherExists {
			return true
		}
		return predicate.ListHasElementsNotIn(val, otherVal)
	case predicate.OpNeqField:
		if !exists {
			return false
		}
		if !otherExists {
			return true
		}
		return !predicate.EqualValues(val, otherVal)
	case predicate.OpNotInField:
		if !exists {
			return true
		}
		if !otherExists {
			return true
		}
		return !predicate.ValueInList(val, otherVal)
	}
	return false
}

func evaluateAnyMatch(ctx EvalContext, exists bool, val, compareVal any) bool {
	if !exists {
		return false
	}
	identities, ok := val.([]asset.CloudIdentity)
	if !ok {
		return false
	}

	// any_match requires a nested predicate structure in the comparison value.
	nested, err := ctx.ParsePredicate(compareVal)
	if nested == nil || err != nil {
		return false
	}

	// Re-use params and parser logic for the nested evaluation.
	idCtx := EvalContext{
		Params:          ctx.Params,
		PredicateParser: ctx.PredicateParser,
	}

	for i := range identities {
		idCtx.Properties = identities[i].Map()
		if nested.EvaluateWithContext(idCtx) {
			return true
		}
	}
	return false
}

// --- Evidence Extraction ---

// ExtractMisconfigurations traverses the predicate tree to pull the actual observed
// values for every field mentioned in the unsafe predicate.
func ExtractMisconfigurations(p *UnsafePredicate, ctx EvalContext) []Misconfiguration {
	if p == nil {
		return nil
	}

	var results []Misconfiguration
	for i := range p.Any {
		p.Any[i].collectFields(ctx, &results)
	}
	for i := range p.All {
		p.All[i].collectFields(ctx, &results)
	}

	// Sort by Property name for stable, deterministic reporting.
	slices.SortFunc(results, func(a, b Misconfiguration) int {
		return cmp.Compare(a.Property, b.Property)
	})

	return results
}

func (r *PredicateRule) collectFields(ctx EvalContext, results *[]Misconfiguration) {
	// Recursive traversal for nested logic blocks
	for i := range r.Any {
		r.Any[i].collectFields(ctx, results)
	}
	for i := range r.All {
		r.All[i].collectFields(ctx, results)
	}

	// Leaf node processing
	if r.Field.IsZero() {
		return
	}

	val, _ := getFieldValueByParts(ctx, r.Field.Parts())

	*results = append(*results, Misconfiguration{
		Property:    r.Field.TrimPrefix(propertiesPathPrefix),
		ActualValue: val,
		Operator:    r.Op,
		UnsafeValue: r.Value.Raw(),
	})
}
