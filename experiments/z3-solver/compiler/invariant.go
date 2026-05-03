package compiler

import (
	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/pkg/stave"
)

// compileInvariants walks every InvariantDefinition in the export
// and produces a CompiledInvariant whose Predicate function takes
// an InvariantEnv and returns the boolean expression representing
// "this configuration is unsafe". The catalog's predicates encode
// the unsafe shape (Stave fires when the predicate holds), so the
// invariant query can answer "does this hold for ALL inputs?" by
// asking Z3 whether the predicate is unsatisfiable.
func (m *CompiledModel) compileInvariants(inv *stave.InvariantExport) error {
	if inv == nil {
		return nil
	}
	for i := range inv.Invariants {
		def := &inv.Invariants[i]
		c := CompiledInvariant{
			ID:         def.ID,
			Severity:   def.Severity,
			Properties: collectProperties(def.Predicate),
			Predicate:  invariantClosure(def.Predicate),
		}
		m.Invariants[def.ID] = c
	}
	return nil
}

// collectProperties walks the predicate tree and returns the
// distinct Property paths the leaves read. Used by callers that
// pre-bind property values from a snapshot before evaluating the
// predicate.
func collectProperties(p stave.PredicateExport) []string {
	seen := map[string]struct{}{}
	walkPredicate(p, func(leaf stave.PredicateExport) {
		if leaf.Property != "" {
			seen[leaf.Property] = struct{}{}
		}
	})
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

// walkPredicate visits every leaf of the predicate tree.
func walkPredicate(p stave.PredicateExport, fn func(stave.PredicateExport)) {
	if p.IsLeaf() {
		fn(p)
		return
	}
	for _, child := range p.Children {
		walkPredicate(child, fn)
	}
}

// invariantClosure returns a function that builds the Z3 boolean
// representing the predicate evaluated against a given env. The
// function captures the predicate tree by value; calling it
// multiple times against the same env produces structurally
// identical Z3 expressions (Z3 dedupes via congruence closure so
// this is harmless).
func invariantClosure(p stave.PredicateExport) func(*InvariantEnv) z3.Bool {
	return func(env *InvariantEnv) z3.Bool {
		return buildPredicate(env, p)
	}
}

// buildPredicate is the recursive translator. Internal nodes
// fold their children with And / Or; leaves emit one operator-
// specific comparison.
func buildPredicate(env *InvariantEnv, p stave.PredicateExport) z3.Bool {
	if !p.IsLeaf() {
		children := make([]z3.Bool, len(p.Children))
		for i := range p.Children {
			children[i] = buildPredicate(env, p.Children[i])
		}
		switch p.Combine {
		case "all":
			return foldAnd(env.Ctx, children)
		case "any":
			return foldOr(env.Ctx, children)
		}
		return env.Ctx.FromBool(true)
	}
	return buildLeaf(env, p)
}

// buildLeaf handles the single-clause encodings. The operator
// vocabulary is the catalog's wire form (eq, ne, gt, lt, present,
// absent, contains, in). Operators outside this set are
// over-approximated as "true" — the caller's NotModeled audit
// surfaces the gap.
func buildLeaf(env *InvariantEnv, p stave.PredicateExport) z3.Bool {
	if p.Property == "" {
		return env.Ctx.FromBool(true)
	}
	switch p.Operator {
	case "eq":
		return leafEqExpr(env, p, true)
	case "ne":
		return leafEqExpr(env, p, false)
	case "present":
		// "present" is encoded as "the property variable is not
		// the distinguished absent constant". For the Z3 closed
		// universe we treat any allocated constant as "present"
		// → trivially true; absent is modeled by the special
		// "absent" string constant the env produces on demand.
		v := env.String(p.Property)
		absent := env.FromString("__absent__")
		return v.Eq(absent).Not()
	case "absent":
		v := env.String(p.Property)
		absent := env.FromString("__absent__")
		return v.Eq(absent)
	case "contains", "in":
		// "X in [a, b, c]" → OR over equalities.
		return leafInExpr(env, p)
	}
	return env.Ctx.FromBool(true)
}

func leafEqExpr(env *InvariantEnv, p stave.PredicateExport, want bool) z3.Bool {
	switch v := p.Expected.(type) {
	case bool:
		expr := env.Bool(p.Property).Eq(env.Ctx.FromBool(v))
		if want {
			return expr
		}
		return expr.Not()
	case string:
		expr := env.String(p.Property).Eq(env.FromString(v))
		if want {
			return expr
		}
		return expr.Not()
	default:
		// Fallback: treat any other Go type as a string via fmt.Sprint.
		expr := env.String(p.Property).Eq(env.FromString(scalarString(v)))
		if want {
			return expr
		}
		return expr.Not()
	}
}

func leafInExpr(env *InvariantEnv, p stave.PredicateExport) z3.Bool {
	values, ok := p.Expected.([]any)
	if !ok || len(values) == 0 {
		return env.Ctx.FromBool(true)
	}
	terms := make([]z3.Bool, 0, len(values))
	for _, v := range values {
		s := scalarString(v)
		terms = append(terms, env.String(p.Property).Eq(env.FromString(s)))
	}
	return foldOr(env.Ctx, terms)
}

// scalarString renders any Go scalar to the string the env's
// FromString uses to allocate uninterpreted constants. Keeps
// "true"/"false" stable for booleans without going through fmt.
func scalarString(v any) string {
	switch x := v.(type) {
	case nil:
		return "__nil__"
	case bool:
		if x {
			return "true"
		}
		return "false"
	case string:
		return x
	default:
		return scalarStringFmt(v)
	}
}
