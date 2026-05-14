// Package predindex provides a shared predicate-AST walker over
// controldef.UnsafePredicate trees. Two consumers today:
//   - internal/tools/genassetschemas (per-asset-type JSON Schema
//     generation — needs property paths plus inferred types)
//   - internal/app/gaps (field-level observation-gap analysis —
//     needs property paths and the controls that read them)
//
// Keeping the AST walk in one place avoids the second consumer
// reinventing the recursion semantics for nested any/all blocks
// and for the forbidden_state predicate (which uses the same
// UnsafePredicate shape).
package predindex

import (
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// Visitor is invoked once per leaf field reference in a control's
// predicate tree. The path is the dot-separated property path
// (already populated, e.g. "properties.storage.kind"); the rule
// pointer gives the caller access to op and value when type
// inference or value enumeration is needed (the schema generator
// uses both; the gaps command uses neither). Callers MUST NOT
// retain the rule pointer beyond the visitor call — the underlying
// slice may be reused.
type Visitor func(controlID kernel.ControlID, rule *policy.PredicateRule, path string)

// WalkPredicate walks the rules in an UnsafePredicate's Any / All
// branches, invoking visit on each field reference (both top-level
// and nested under further any/all blocks). Returns immediately
// for nil or empty predicates so callers can pass
// ControlDefinition.UnsafePredicate AND ControlDefinition.ForbiddenState
// uniformly (the same shape underlies both).
func WalkPredicate(p *policy.UnsafePredicate, controlID kernel.ControlID, visit Visitor) {
	if p == nil || p.IsEmpty() {
		return
	}
	for i := range p.Any {
		WalkRule(&p.Any[i], controlID, visit)
	}
	for i := range p.All {
		WalkRule(&p.All[i], controlID, visit)
	}
}

// WalkRule walks one PredicateRule, invoking visit on its field
// reference (if it's a leaf) and recursing into any nested any/all
// blocks. A rule with a non-empty Field is a leaf — even if it
// also has Any/All children, predicate semantics evaluate the
// leaf first; the walker matches that ordering by emitting the
// leaf before recursing.
func WalkRule(r *policy.PredicateRule, controlID kernel.ControlID, visit Visitor) {
	if !r.Field.IsZero() {
		visit(controlID, r, r.Field.String())
	}
	for i := range r.Any {
		WalkRule(&r.Any[i], controlID, visit)
	}
	for i := range r.All {
		WalkRule(&r.All[i], controlID, visit)
	}
}

// WalkControl is the common case: walk both UnsafePredicate AND
// ForbiddenState for a single control. Centralised so callers
// stop having to remember the second predicate shape.
func WalkControl(ctl *policy.ControlDefinition, visit Visitor) {
	WalkPredicate(&ctl.UnsafePredicate, ctl.ID, visit)
	WalkPredicate(&ctl.ForbiddenState, ctl.ID, visit)
}
