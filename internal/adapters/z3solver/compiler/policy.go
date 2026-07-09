//go:build cgo && z3

package compiler

import (
	"fmt"
	"strings"

	"github.com/aclements/go-z3/z3"
)

func (m *CompiledModel) compilePolicies(p *PolicyExport) error {
	if p == nil {
		return nil
	}
	addDocs := func(docs []PolicyDocument) {
		for i := range docs {
			m.compileDoc(&docs[i])
		}
	}
	addDocs(p.ResourcePolicies)
	addDocs(p.KMSKeyPolicies)

	for i := range p.TrustPolicies {
		m.compileTrustDoc(&p.TrustPolicies[i])
	}
	return nil
}

func (m *CompiledModel) compileDoc(doc *PolicyDocument) {
	for i := range doc.Statements {
		stmt := &doc.Statements[i]
		assertionName := fmt.Sprintf("policy:%s|%s|%s|%d",
			doc.SourceAssetID, doc.PolicyType, stmt.Sid, i)
		m.appendStatement(stmt, doc.SourceAssetID, doc.PolicyType, assertionName, false)
	}
}

func (m *CompiledModel) compileTrustDoc(doc *TrustDocument) {
	for i := range doc.Statements {
		stmt := &doc.Statements[i]
		assertionName := fmt.Sprintf("trust:%s|%s|%d",
			doc.SourceAssetID, stmt.Sid, i)
		m.appendStatement(stmt, doc.SourceAssetID, "trust", assertionName, true)

		for _, p := range stmt.Principals {
			bare := stripCategoryPrefix(p)
			if bare == "" || bare == "*" {
				continue
			}
			m.TrustEdges = append(m.TrustEdges, TrustEdge{
				Assumer: bare,
				Assumee: doc.SourceAssetID,
			})
		}
	}
}

type queryVars struct {
	P z3.Uninterpreted
	A z3.Uninterpreted
	R z3.Uninterpreted
}

func (m *CompiledModel) freshQueryVars(prefix string) queryVars {
	return queryVars{
		P: m.Ctx.Const(prefix+"_principal", m.PrincipalSort).(z3.Uninterpreted),
		A: m.Ctx.Const(prefix+"_action", m.ActionSort).(z3.Uninterpreted),
		R: m.Ctx.Const(prefix+"_resource", m.ResourceSort).(z3.Uninterpreted),
	}
}

func (m *CompiledModel) appendStatement(stmt *PolicyStatement, sourceAsset, policyType, assertionName string, isTrust bool) {
	vars := m.evalVars()

	var notModeled []string
	principalMatch := m.matchSet(vars.P, stmt.Principals, stmt.NotPrincipals, m.Principals)
	actionMatch := m.matchActionSet(vars.A, stmt.Actions, stmt.NotActions)
	resourceMatch := m.matchResourceSet(vars.R, stmt.Resources, stmt.NotResources, sourceAsset, isTrust)
	conditionMatch, condGaps := m.compileConditions(stmt.Conditions)
	notModeled = append(notModeled, condGaps...)

	cs := CompiledStatement{
		SourceAssetID:  sourceAsset,
		PolicyType:     policyType,
		Sid:            stmt.Sid,
		Effect:         stmt.Effect,
		PrincipalMatch: principalMatch,
		ActionMatch:    actionMatch,
		ResourceMatch:  resourceMatch,
		ConditionMatch: conditionMatch,
		AssertionName:  assertionName,
		NotModeled:     notModeled,
	}
	m.Stmt = append(m.Stmt, cs)
}

func (m *CompiledModel) evalVars() queryVars {
	if m.evalVarsCache != nil {
		return *m.evalVarsCache
	}
	v := m.freshQueryVars("eval")
	m.evalVarsCache = &v
	return v
}

func (m *CompiledModel) matchSet(sym z3.Uninterpreted, allow, deny []string, universe map[string]z3.Uninterpreted) z3.Bool {
	allowMatch := m.matchPrincipals(sym, allow, universe)
	if len(deny) == 0 {
		return allowMatch
	}
	denyMatch := m.matchPrincipals(sym, deny, universe)
	return allowMatch.And(denyMatch.Not())
}

func (m *CompiledModel) matchPrincipals(sym z3.Uninterpreted, refs []string, universe map[string]z3.Uninterpreted) z3.Bool {
	if len(refs) == 0 {
		return m.Ctx.FromBool(true)
	}
	for _, p := range refs {
		bare := stripCategoryPrefix(p)
		if bare == "*" {
			return m.Ctx.FromBool(true)
		}
	}
	disjuncts := []z3.Bool{}
	for _, p := range refs {
		bare := stripCategoryPrefix(p)
		c, ok := universe[bare]
		if !ok {
			continue
		}
		disjuncts = append(disjuncts, sym.Eq(c))
	}
	return foldOr(m.Ctx, disjuncts)
}

func (m *CompiledModel) matchActionSet(sym z3.Uninterpreted, allow, deny []string) z3.Bool {
	allowMatch := m.matchActions(sym, allow)
	if len(deny) == 0 {
		return allowMatch
	}
	denyMatch := m.matchActions(sym, deny)
	return allowMatch.And(denyMatch.Not())
}

func (m *CompiledModel) matchActions(sym z3.Uninterpreted, refs []string) z3.Bool {
	if len(refs) == 0 {
		return m.Ctx.FromBool(true)
	}
	matched := []z3.Bool{}
	for _, pattern := range refs {
		for action, c := range m.Actions {
			if matchPattern(action, pattern) {
				matched = append(matched, sym.Eq(c))
			}
		}
		if pattern == "*" {
			return m.Ctx.FromBool(true)
		}
	}
	return foldOr(m.Ctx, matched)
}

func (m *CompiledModel) matchResourceSet(sym z3.Uninterpreted, allow, deny []string, sourceAsset string, isTrust bool) z3.Bool {
	if isTrust && len(allow) == 0 {
		c, ok := m.Resources[sourceAsset]
		if !ok {
			return m.Ctx.FromBool(true)
		}
		return sym.Eq(c)
	}
	allowMatch := m.matchResources(sym, allow)
	if len(deny) == 0 {
		return allowMatch
	}
	denyMatch := m.matchResources(sym, deny)
	return allowMatch.And(denyMatch.Not())
}

func (m *CompiledModel) matchResources(sym z3.Uninterpreted, refs []string) z3.Bool {
	if len(refs) == 0 {
		return m.Ctx.FromBool(true)
	}
	matched := []z3.Bool{}
	for _, pattern := range refs {
		if pattern == "*" {
			return m.Ctx.FromBool(true)
		}
		for resource, c := range m.Resources {
			if matchPattern(resource, pattern) {
				matched = append(matched, sym.Eq(c))
			}
		}
	}
	return foldOr(m.Ctx, matched)
}

func matchPattern(value, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if value == pattern {
		return true
	}
	if strings.Contains(pattern, "*") {
		idx := strings.Index(pattern, "*")
		prefix := pattern[:idx]
		suffix := pattern[idx+1:]
		if !strings.HasPrefix(value, prefix) {
			return false
		}
		if suffix == "" {
			return true
		}
		if strings.Contains(suffix, "*") {
			parts := strings.Split(pattern, "*")
			cursor := 0
			for _, part := range parts {
				if part == "" {
					continue
				}
				idx := strings.Index(value[cursor:], part)
				if idx < 0 {
					return false
				}
				cursor += idx + len(part)
			}
			return true
		}
		return strings.HasSuffix(value, suffix)
	}
	return false
}

func foldOr(ctx *z3.Context, terms []z3.Bool) z3.Bool {
	if len(terms) == 0 {
		return ctx.FromBool(false)
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return terms[0].Or(terms[1:]...)
}

func foldAnd(ctx *z3.Context, terms []z3.Bool) z3.Bool {
	if len(terms) == 0 {
		return ctx.FromBool(true)
	}
	if len(terms) == 1 {
		return terms[0]
	}
	return terms[0].And(terms[1:]...)
}

// EvalVarsExported returns the (P, A, R) triple for query use.
func (m *CompiledModel) EvalVarsExported() (z3.Uninterpreted, z3.Uninterpreted, z3.Uninterpreted) {
	v := m.evalVars()
	return v.P, v.A, v.R
}

// EvaluateAccess folds every statement into a single boolean
// representing the AWS IAM evaluation order.
func (m *CompiledModel) EvaluateAccess() z3.Bool {
	return m.EvaluateAccessWith(nil)
}

// EvaluateAccessWith is the suppression-aware variant.
func (m *CompiledModel) EvaluateAccessWith(suppressed map[int]struct{}) z3.Bool {
	allows := []z3.Bool{}
	denies := []z3.Bool{}
	for i := range m.Stmt {
		if _, ok := suppressed[i]; ok {
			continue
		}
		s := &m.Stmt[i]
		match := s.PrincipalMatch.And(s.ActionMatch, s.ResourceMatch, s.ConditionMatch)
		switch s.Effect {
		case "Allow":
			allows = append(allows, match)
		case "Deny":
			denies = append(denies, match)
		}
	}
	allowExpr := foldOr(m.Ctx, allows)
	denyExpr := foldOr(m.Ctx, denies)
	return allowExpr.And(denyExpr.Not())
}
