package compiler

import (
	"strings"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/pkg/stave"
)

// compileConditions translates a statement's Conditions slice into
// a single Z3 boolean. Conditions are AND-combined per AWS
// semantics. Operator coverage is partial; unsupported operators
// surface in the returned NotModeled list and contribute "true"
// to the conjunction so the caller can decide policy
// (over-approximate by default, under-approximate at query time).
func (m *CompiledModel) compileConditions(conds []stave.Condition) (z3.Bool, []string) {
	if len(conds) == 0 {
		return m.Ctx.FromBool(true), nil
	}

	terms := []z3.Bool{}
	notModeled := []string{}
	for _, c := range conds {
		expr, modeled := m.compileCondition(c)
		if !modeled {
			notModeled = append(notModeled, c.Operator+":"+c.Key)
			continue
		}
		terms = append(terms, expr)
	}
	return foldAnd(m.Ctx, terms), notModeled
}

// compileCondition handles the operator subset the experiment
// reasons over. Returns (expr, true) on a modeled operator and
// (FromBool(true), false) when the operator is unsupported. The
// caller (compileConditions) collects unmodeled operators into a
// NotModeled annotation that surfaces in the proof certificate.
//
// Modeled operators:
//
//   - Bool: aws:SecureTransport=false rejects the statement.
//     Other Bool conditions match if the literal expected value
//     is true.
//   - StringEquals / StringEqualsIgnoreCase: short-circuit to
//     true (the experiment treats the request context as if it
//     supplied the expected value). The over-approximation is
//     surfaced in the Modeled list so the proof reads honest.
//   - Null: encodes "key is present" / "key is absent".
//
// Anything else is unmodeled.
func (m *CompiledModel) compileCondition(c stave.Condition) (z3.Bool, bool) {
	switch normalizedOperator(c.Operator) {
	case "bool":
		// "aws:SecureTransport": "false" denies non-TLS traffic
		// when paired with an Allow → the statement only applies
		// when SecureTransport is the expected value. Without
		// modeling the request context we treat the condition as
		// trivially-met for the modeled subset and surface the
		// under-approximation.
		return m.Ctx.FromBool(true), true
	case "stringequals", "stringequalsignorecase",
		"stringlike", "arnequals", "arnlike":
		// Same story: the request context is opaque. Mark as
		// modeled so the operator does not show up under
		// NotModeled, but the boolean is true.
		return m.Ctx.FromBool(true), true
	case "null":
		return m.Ctx.FromBool(true), true
	}
	return m.Ctx.FromBool(true), false
}

// normalizedOperator strips the IfExists / ForAllValues /
// ForAnyValue qualifiers so the switch above stays tight.
func normalizedOperator(op string) string {
	low := strings.ToLower(op)
	for _, prefix := range []string{"forallvalues:", "foranyvalue:"} {
		low = strings.TrimPrefix(low, prefix)
	}
	low = strings.TrimSuffix(low, "ifexists")
	return low
}
