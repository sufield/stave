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
// modeled as four Bools: has_field (present?), eq_field (equals
// expected value?), empty_field (value is empty/nil?), and
// typemismatch_field (value type differs from predicate value type?).
// The type-mismatch variable captures the key divergence: CEL is
// typed (mismatch → error → false), while the reference evaluator
// uses Sprint-based comparison (type-agnostic).
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
			hasVar:          ctx.BoolConst("has_" + name),
			eqVar:           ctx.BoolConst("eq_" + name),
			isEmptyVar:      ctx.BoolConst("empty_" + name),
			typeMismatchVar: ctx.BoolConst("typemismatch_" + name),
			gtVar:           ctx.BoolConst("gt_" + name),
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
			mv := m.Eval(sf.isEmptyVar, true)
			tv := m.Eval(sf.typeMismatchVar, true)
			gv := m.Eval(sf.gtVar, true)
			witness = append(witness, fmt.Sprintf("%s(has=%s,eq=%s,empty=%s,typemismatch=%s,gt=%s)", short, hv, ev, mv, tv, gv))
		}
		return symbolicResult{
			Status: "DIVERGE",
			Detail: "counterexample: {" + strings.Join(witness, ", ") + "}",
		}
	}

	return symbolicResult{Status: "EQUIV", Detail: "proved equivalent for all inputs"}
}

type symField struct {
	hasVar          z3.Bool
	eqVar           z3.Bool
	isEmptyVar      z3.Bool
	typeMismatchVar z3.Bool
	gtVar           z3.Bool // field value > expected value
}

// buildFormula translates the reference (formal spec) semantics.
// The reference evaluator uses Sprint-based comparison (type-agnostic),
// so type mismatches do not affect the result.
func buildFormula(ctx *z3.Context, pred policy.UnsafePredicate, syms map[string]symField) z3.Bool {
	return buildPredicateFormula(ctx, pred, syms, false)
}

// buildCELFormula translates the CEL compiler's semantics.
// CEL uses typed comparison: a type mismatch between the field value
// and the predicate value causes a runtime error, which the evaluator
// treats as false.
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

	if celMode {
		return buildRuleCEL(ctx, r.Op, sf)
	}
	return buildRuleRef(ctx, r.Op, sf)
}

// buildRuleRef encodes the reference evaluator's semantics.
// Sprint-based comparison: type mismatches are invisible.
func buildRuleRef(ctx *z3.Context, op predicate.Operator, sf symField) z3.Bool {
	switch op {
	case predicate.OpEq:
		// hasField ∧ eq (Sprint comparison, type-agnostic)
		return sf.hasVar.And(sf.eqVar)

	case predicate.OpNe:
		// ¬hasField ∨ ¬eq (Sprint comparison, type-agnostic)
		return sf.hasVar.Not().Or(sf.eqVar.Not())

	case predicate.OpGt:
		// hasField ∧ gt (type-agnostic numeric comparison)
		return sf.hasVar.And(sf.gtVar)

	case predicate.OpGte:
		// hasField ∧ (gt ∨ eq)
		return sf.hasVar.And(sf.gtVar.Or(sf.eqVar))

	case predicate.OpLt:
		// hasField ∧ ¬gt ∧ ¬eq
		return sf.hasVar.And(sf.gtVar.Not()).And(sf.eqVar.Not())

	case predicate.OpLte:
		// hasField ∧ (¬gt ∨ eq) ≡ hasField ∧ ¬(gt ∧ ¬eq)
		return sf.hasVar.And(sf.gtVar.Not().Or(sf.eqVar))

	case predicate.OpMissing:
		// ¬hasField ∨ isEmpty (isMissing checks nil/empty-string/empty-list/empty-map)
		return sf.hasVar.Not().Or(sf.isEmptyVar)

	case predicate.OpPresent:
		// hasField ∧ ¬isEmpty
		return sf.hasVar.And(sf.isEmptyVar.Not())

	default:
		return ctx.FromBool(true)
	}
}

// buildRuleCEL encodes the CEL evaluator's semantics.
// Typed comparison: type mismatch → runtime error → false.
func buildRuleCEL(ctx *z3.Context, op predicate.Operator, sf symField) z3.Bool {
	switch op {
	case predicate.OpEq:
		// has ∧ ¬typeMismatch ∧ eq
		// CEL: (has(field) && field == value) — type mismatch errors → false
		return sf.hasVar.And(sf.typeMismatchVar.Not()).And(sf.eqVar)

	case predicate.OpNe:
		// ¬has ∨ (¬typeMismatch ∧ ¬eq)
		// CEL: (!has(field) || field != value) — if has but type mismatch,
		// the != comparison errors; false || error → error → false
		return sf.hasVar.Not().Or(sf.typeMismatchVar.Not().And(sf.eqVar.Not()))

	case predicate.OpGt:
		// has ∧ ¬typeMismatch ∧ gt
		return sf.hasVar.And(sf.typeMismatchVar.Not()).And(sf.gtVar)

	case predicate.OpGte:
		// has ∧ ¬typeMismatch ∧ (gt ∨ eq)
		return sf.hasVar.And(sf.typeMismatchVar.Not()).And(sf.gtVar.Or(sf.eqVar))

	case predicate.OpLt:
		// has ∧ ¬typeMismatch ∧ ¬gt ∧ ¬eq
		return sf.hasVar.And(sf.typeMismatchVar.Not()).And(sf.gtVar.Not()).And(sf.eqVar.Not())

	case predicate.OpLte:
		// has ∧ ¬typeMismatch ∧ (¬gt ∨ eq)
		return sf.hasVar.And(sf.typeMismatchVar.Not()).And(sf.gtVar.Not().Or(sf.eqVar))

	case predicate.OpMissing:
		// ¬hasField ∨ isEmpty (CEL missing() checks same emptiness conditions)
		return sf.hasVar.Not().Or(sf.isEmptyVar)

	case predicate.OpPresent:
		// hasField ∧ ¬isEmpty
		return sf.hasVar.And(sf.isEmptyVar.Not())

	default:
		return ctx.FromBool(true)
	}
}

func sanitizeName(path string) string {
	return strings.ReplaceAll(strings.ReplaceAll(path, ".", "_"), "-", "_")
}
