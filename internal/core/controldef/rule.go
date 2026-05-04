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

	var misconfigurations []Misconfiguration
	for i := range p.Any {
		misconfigurations = p.Any[i].collect(ctx, misconfigurations)
	}
	for i := range p.All {
		misconfigurations = p.All[i].collect(ctx, misconfigurations)
	}

	if len(misconfigurations) == 0 {
		return nil
	}

	// Sort by Property, Operator, then UnsafeValue for fully deterministic output.
	slices.SortFunc(misconfigurations, func(a, b Misconfiguration) int {
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
	return slices.CompactFunc(misconfigurations, func(a, b Misconfiguration) bool {
		return a.Property.String() == b.Property.String() &&
			a.Operator == b.Operator &&
			fmt.Sprint(a.UnsafeValue) == fmt.Sprint(b.UnsafeValue)
	})
}

// collect appends discovered misconfigurations and returns the updated slice.
func (r *PredicateRule) collect(ctx *EvalContext, misconfigurations []Misconfiguration) []Misconfiguration {
	for i := range r.Any {
		misconfigurations = r.Any[i].collect(ctx, misconfigurations)
	}
	for i := range r.All {
		misconfigurations = r.All[i].collect(ctx, misconfigurations)
	}

	if r.Field.IsZero() {
		return misconfigurations
	}

	val, found := resolvePropertyValue(ctx.PropertyMap(), r.Field.Parts())

	return append(misconfigurations, Misconfiguration{
		Property: predicate.NewFieldPath(r.Field.TrimPrefix(propertiesPathPrefix)),
		// Only record val when the field was actually present. The
		// previous (val, _) shape collapsed "field absent" and "field
		// has nil value" into the same evidence row — operators
		// triaging a finding could not tell which condition fired.
		ActualValue: val,
		FieldAbsent: !found,
		Operator:    r.Op,
		UnsafeValue: r.Value.Raw(),
		Category:    classifyProperty(r.Field.String()),
	})
}
