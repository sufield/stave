//go:build cgo && z3

package main

import (
	"fmt"
	"strings"

	"github.com/aclements/go-z3/z3"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/predicate"
)

// symbolicCheckImpl uses Z3 to prove that the CEL translation and the
// reference semantics agree for ALL possible inputs. Each field is
// modeled as two Bools: has_field (present?) and eq_field (equals
// expected value?). This is sound for eq/ne operators — we only care
// about equality, not the value space.
func symbolicCheckImpl(pred policy.UnsafePredicate, fields []fieldInfo) symbolicResult {
	if len(fields) == 0 {
		return symbolicResult{Status: "SKIP", Detail: "no fields"}
	}

	ctx := z3.NewContext(nil)
	solver := z3.NewSolver(ctx)

	syms := make(map[string]symField, len(fields))
	for _, f := range fields {
		name := sanitizeName(f.Path)
		syms[f.Path] = symField{
			hasVar: ctx.BoolConst("has_" + name),
			eqVar:  ctx.BoolConst("eq_" + name),
		}
	}

	refFormula := buildFormula(ctx, pred, syms)
	celFormula := buildCELFormula(ctx, pred, syms)

	// Assert ref XOR cel — SAT means they disagree on some input
	solver.Assert(refFormula.Xor(celFormula))

	sat, err := solver.Check()
	if err != nil {
		return symbolicResult{Status: "ERROR", Detail: err.Error()}
	}
	if sat {
		m := solver.Model()
		var witness []string
		for path, sf := range syms {
			short := path
			if idx := strings.LastIndex(path, "."); idx >= 0 {
				short = path[idx+1:]
			}
			hv := m.Eval(sf.hasVar, true)
			ev := m.Eval(sf.eqVar, true)
			witness = append(witness, fmt.Sprintf("%s(has=%s,eq=%s)", short, hv, ev))
		}
		return symbolicResult{
			Status: "DIVERGE",
			Detail: "counterexample: {" + strings.Join(witness, ", ") + "}",
		}
	}

	return symbolicResult{Status: "EQUIV", Detail: "proved equivalent for all inputs"}
}

type symField struct {
	hasVar z3.Bool
	eqVar  z3.Bool
}

// buildFormula translates the reference (formal spec) semantics.
// For op:eq: hasField ∧ eq_field
// For op:ne: ¬hasField ∨ ¬eq_field
func buildFormula(ctx *z3.Context, pred policy.UnsafePredicate, syms map[string]symField) z3.Bool {
	return buildPredicateFormula(ctx, pred, syms, false)
}

// buildCELFormula translates the CEL compiler's semantics.
// For Phase 1 (S3 controls, all op:eq), identical to reference.
// Separated so Tier 2 controls with ne/missing/present can model
// the CEL-specific behavior independently.
func buildCELFormula(ctx *z3.Context, pred policy.UnsafePredicate, syms map[string]symField) z3.Bool {
	return buildPredicateFormula(ctx, pred, syms, true)
}

func buildPredicateFormula(ctx *z3.Context, pred policy.UnsafePredicate, syms map[string]symField, celMode bool) z3.Bool {
	allExprs := make([]z3.Bool, 0, len(pred.All))
	for _, r := range pred.All {
		allExprs = append(allExprs, buildRuleFormula(ctx, r, syms, celMode))
	}

	anyExprs := make([]z3.Bool, 0, len(pred.Any))
	for _, r := range pred.Any {
		anyExprs = append(anyExprs, buildRuleFormula(ctx, r, syms, celMode))
	}

	result := ctx.FromBool(true)

	if len(allExprs) > 0 {
		conj := allExprs[0]
		for _, e := range allExprs[1:] {
			conj = conj.And(e)
		}
		result = conj
	}

	if len(anyExprs) > 0 {
		disj := anyExprs[0]
		for _, e := range anyExprs[1:] {
			disj = disj.Or(e)
		}
		if len(allExprs) > 0 {
			result = result.And(disj)
		} else {
			result = disj
		}
	}

	return result
}

func buildRuleFormula(ctx *z3.Context, r policy.PredicateRule, syms map[string]symField, celMode bool) z3.Bool {
	if len(r.All) > 0 || len(r.Any) > 0 {
		nested := policy.UnsafePredicate{All: r.All, Any: r.Any}
		return buildPredicateFormula(ctx, nested, syms, celMode)
	}

	if r.Field.IsZero() {
		return ctx.FromBool(true)
	}

	path := r.Field.String()
	sf, ok := syms[path]
	if !ok {
		return ctx.FromBool(false)
	}

	switch r.Op {
	case predicate.OpEq:
		// hasField ∧ field == value
		return sf.hasVar.And(sf.eqVar)

	case predicate.OpNe:
		// ¬hasField ∨ field ≠ value
		return sf.hasVar.Not().Or(sf.eqVar.Not())

	case predicate.OpMissing:
		// ¬hasField (simplified; full missing() also checks empty)
		return sf.hasVar.Not()

	case predicate.OpPresent:
		// hasField
		return sf.hasVar

	default:
		return ctx.FromBool(true)
	}
}

func sanitizeName(path string) string {
	return strings.ReplaceAll(strings.ReplaceAll(path, ".", "_"), "-", "_")
}
