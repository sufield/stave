//go:build cgo && z3

package compiler

import (
	"github.com/aclements/go-z3/z3"
)

func (m *CompiledModel) compileInvariants(inv *InvariantExport) error {
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

func collectProperties(p PredicateExport) []string {
	seen := map[string]struct{}{}
	walkPredicate(p, func(leaf PredicateExport) {
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

func walkPredicate(p PredicateExport, fn func(PredicateExport)) {
	if p.IsLeaf() {
		fn(p)
		return
	}
	for _, child := range p.Children {
		walkPredicate(child, fn)
	}
}

func invariantClosure(p PredicateExport) func(*InvariantEnv) z3.Bool {
	return func(env *InvariantEnv) z3.Bool {
		return buildPredicate(env, p)
	}
}

func buildPredicate(env *InvariantEnv, p PredicateExport) z3.Bool {
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

func buildLeaf(env *InvariantEnv, p PredicateExport) z3.Bool {
	if p.Property == "" {
		return env.Ctx.FromBool(true)
	}
	switch p.Operator {
	case "eq":
		return leafEqExpr(env, p, true)
	case "ne":
		return leafEqExpr(env, p, false)
	case "present":
		v := env.String(p.Property)
		absent := env.FromString("__absent__")
		return v.Eq(absent).Not()
	case "absent":
		v := env.String(p.Property)
		absent := env.FromString("__absent__")
		return v.Eq(absent)
	case "contains", "in":
		return leafInExpr(env, p)
	}
	return env.Ctx.FromBool(true)
}

func leafEqExpr(env *InvariantEnv, p PredicateExport, want bool) z3.Bool {
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
		expr := env.String(p.Property).Eq(env.FromString(scalarString(v)))
		if want {
			return expr
		}
		return expr.Not()
	}
}

func leafInExpr(env *InvariantEnv, p PredicateExport) z3.Bool {
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
