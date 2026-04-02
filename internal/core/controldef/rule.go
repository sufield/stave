package controldef

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/sufield/stave/internal/core/predicate"
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

// ExtractMisconfigurations traverses the predicate tree to pull the actual observed
// values for every field mentioned in the unsafe predicate.
// Returns a sorted, deduplicated slice of misconfigurations.
func ExtractMisconfigurations(p *UnsafePredicate, ctx *EvalContext) []Misconfiguration {
	if p == nil {
		return nil
	}

	var results []Misconfiguration
	for i := range p.Any {
		results = p.Any[i].collect(ctx, results)
	}
	for i := range p.All {
		results = p.All[i].collect(ctx, results)
	}

	if len(results) == 0 {
		return nil
	}

	// Sort by Property, Operator, then UnsafeValue for fully deterministic output.
	slices.SortFunc(results, func(a, b Misconfiguration) int {
		if n := cmp.Compare(a.Property.String(), b.Property.String()); n != 0 {
			return n
		}
		if n := cmp.Compare(string(a.Operator), string(b.Operator)); n != 0 {
			return n
		}
		return cmp.Compare(fmt.Sprint(a.UnsafeValue), fmt.Sprint(b.UnsafeValue))
	})

	// Remove adjacent duplicates (same property checked multiple times in a logic tree).
	// Uses fmt.Sprint for UnsafeValue since it is type any and may not be comparable with ==.
	return slices.CompactFunc(results, func(a, b Misconfiguration) bool {
		return a.Property.String() == b.Property.String() &&
			a.Operator == b.Operator &&
			fmt.Sprint(a.UnsafeValue) == fmt.Sprint(b.UnsafeValue)
	})
}

// collect appends discovered misconfigurations and returns the updated slice.
func (r *PredicateRule) collect(ctx *EvalContext, results []Misconfiguration) []Misconfiguration {
	for i := range r.Any {
		results = r.Any[i].collect(ctx, results)
	}
	for i := range r.All {
		results = r.All[i].collect(ctx, results)
	}

	if r.Field.IsZero() {
		return results
	}

	val, _ := resolvePropertyValue(ctx.Properties, r.Field.Parts())

	return append(results, Misconfiguration{
		Property:    predicate.NewFieldPath(r.Field.TrimPrefix(propertiesPathPrefix)),
		ActualValue: val,
		Operator:    r.Op,
		UnsafeValue: r.Value.Raw(),
		Category:    classifyProperty(r.Field.String()),
	})
}
