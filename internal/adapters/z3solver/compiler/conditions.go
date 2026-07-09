//go:build cgo && z3

package compiler

import (
	"strings"

	"github.com/aclements/go-z3/z3"
)

func (m *CompiledModel) compileConditions(conds []Condition) (z3.Bool, []string) {
	if len(conds) == 0 {
		return m.Ctx.FromBool(true), nil
	}

	var terms []z3.Bool
	var notModeled []string
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

func (m *CompiledModel) compileCondition(c Condition) (z3.Bool, bool) {
	switch normalizedOperator(c.Operator) {
	case "bool":
		return m.Ctx.FromBool(true), true
	case "stringequals", "stringequalsignorecase",
		"stringlike", "arnequals", "arnlike":
		return m.Ctx.FromBool(true), true
	case "null":
		return m.Ctx.FromBool(true), true
	}
	return m.Ctx.FromBool(true), false
}

func normalizedOperator(op string) string {
	low := strings.ToLower(op)
	for _, prefix := range []string{"forallvalues:", "foranyvalue:"} {
		low = strings.TrimPrefix(low, prefix)
	}
	low = strings.TrimSuffix(low, "ifexists")
	return low
}
