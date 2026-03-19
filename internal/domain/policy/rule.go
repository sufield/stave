package policy

import (
	"cmp"
	"slices"

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

	val, _ := resolvePropertyValue(ctx.Properties, r.Field.Parts())

	*results = append(*results, Misconfiguration{
		Property:    r.Field.TrimPrefix(propertiesPathPrefix),
		ActualValue: val,
		Operator:    r.Op,
		UnsafeValue: r.Value.Raw(),
	})
}
