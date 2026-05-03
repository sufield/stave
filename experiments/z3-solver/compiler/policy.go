package compiler

import (
	"fmt"
	"strings"

	"github.com/aclements/go-z3/z3"

	"github.com/sufield/stave/pkg/stave"
)

// compilePolicies walks every PolicyDocument in the export
// (resource policies, KMS key policies, trust policies) and
// produces a CompiledStatement per statement. The match functions
// are pre-computed against the symbolic (P, A, R) variables the
// IAM evaluator allocates — see EvaluateAccess.
func (m *CompiledModel) compilePolicies(p *stave.PolicyExport) error {
	if p == nil {
		return nil
	}
	addDocs := func(docs []stave.PolicyDocument) {
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

func (m *CompiledModel) compileDoc(doc *stave.PolicyDocument) {
	for i := range doc.Statements {
		stmt := &doc.Statements[i]
		assertionName := fmt.Sprintf("policy:%s|%s|%s|%d",
			doc.SourceAssetID, doc.PolicyType, stmt.Sid, i)
		m.appendStatement(stmt, doc.SourceAssetID, doc.PolicyType, assertionName, false)
	}
}

func (m *CompiledModel) compileTrustDoc(doc *stave.TrustDocument) {
	for i := range doc.Statements {
		stmt := &doc.Statements[i]
		assertionName := fmt.Sprintf("trust:%s|%s|%d",
			doc.SourceAssetID, stmt.Sid, i)
		m.appendStatement(stmt, doc.SourceAssetID, "trust", assertionName, true)

		// Trust policies imply assume-edges from each AWS principal
		// to the role: the graph compiler reads this slice when
		// expanding multi-hop reachability.
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

// queryVars holds the symbolic principal/action/resource the IAM
// evaluator threads through every match function. Built once per
// query so distinct queries do not collide on variable identity.
type queryVars struct {
	P z3.Uninterpreted
	A z3.Uninterpreted
	R z3.Uninterpreted
}

// freshQueryVars allocates fresh symbolic (P, A, R) constants in
// the model's three uninterpreted sorts. Returned every time a
// query starts so two queries running back-to-back see distinct
// variable identities even if they share the model.
func (m *CompiledModel) freshQueryVars(prefix string) queryVars {
	return queryVars{
		P: m.Ctx.Const(prefix+"_principal", m.PrincipalSort).(z3.Uninterpreted),
		A: m.Ctx.Const(prefix+"_action", m.ActionSort).(z3.Uninterpreted),
		R: m.Ctx.Const(prefix+"_resource", m.ResourceSort).(z3.Uninterpreted),
	}
}

// appendStatement walks one PolicyStatement and produces the
// CompiledStatement appended to the model. The match expressions
// are built against fresh symbolic variables stamped onto the
// model the first time appendStatement is called — a single
// (P, A, R) triple is shared across every statement so the IAM
// evaluator can fold them with And/Or without re-binding.
func (m *CompiledModel) appendStatement(stmt *stave.PolicyStatement, sourceAsset, policyType, assertionName string, isTrust bool) {
	vars := m.evalVars()

	notModeled := []string{}
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

// evalVars returns the (P, A, R) triple every CompiledStatement
// matches against. Allocated once per model so the IAM-evaluation
// fold builds a single-variable expression rather than a
// per-statement one. EvaluateAccess re-uses this triple.
func (m *CompiledModel) evalVars() queryVars {
	if m.evalVarsCache != nil {
		return *m.evalVarsCache
	}
	v := m.freshQueryVars("eval")
	m.evalVarsCache = &v
	return v
}

// matchSet expands the wildcard semantics for the principal slot:
// "*" matches every constant in the model's principal universe;
// any specific ARN matches its own constant. NotPrincipals
// contributes a negation: if the symbolic value is in the
// not-set, the statement does not match.
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
		// No Principal ⇒ the statement does not constrain the
		// principal at all; match by default. Bucket policies
		// with no Principal are rejected by AWS at deploy time
		// — Stave's wire-form preserves the absence so the
		// compiler can surface the issue separately.
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

// matchActionSet handles the "s3:*" / specific-action / NotAction
// shapes by expanding each pattern against the model's action
// universe. Wildcards match any action whose name shares the
// pattern's prefix-before-"*" segment.
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

// matchResourceSet expands resource patterns against the model's
// resource universe. For trust policies the Resource field is
// often empty; AWS treats that as "the role itself", so when
// isTrust is true and refs is empty, we match against the source
// asset's constant.
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

// matchPattern reports whether the literal value satisfies the
// AWS-style pattern. Supported wildcards: "*" anywhere (collapsed
// to prefix/suffix match) and the trailing "/*" form for ARN paths.
// Unsupported wildcards (e.g. "?" character) fall back to literal
// equality.
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
			// Multi-wildcard: fall back to "contains every
			// segment in order" match. Not common in IAM
			// policies; covers cases like "arn:*:s3:::b/*".
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

// EvalVarsExported returns the (P, A, R) triple every CompiledStatement
// matches against. Queries use this to constrain the variables to
// their query-specific values before calling EvaluateAccess.
func (m *CompiledModel) EvalVarsExported() (z3.Uninterpreted, z3.Uninterpreted, z3.Uninterpreted) {
	v := m.evalVars()
	return v.P, v.A, v.R
}

// EvaluateAccess folds every CompiledStatement into a single
// boolean expression representing the AWS evaluation order:
//
//	access = AnyIdentityOrResourceAllow AND NOT(AnyExplicitDeny)
//
// Today's model covers Allow / Deny in identity and resource
// policies (including KMS key policies). SCPs, permissions
// boundaries, session policies, and VPC-endpoint policies are NOT
// modeled — the result of EvaluateAccess is a sound under-
// approximation for those layers (a pure ALLOW means "no modeled
// layer denies"; the unmodeled layers may still deny in production).
func (m *CompiledModel) EvaluateAccess() z3.Bool {
	return m.EvaluateAccessWith(nil)
}

// EvaluateAccessWith is the suppression-aware variant of
// EvaluateAccess: any index in the supplied set is treated as if
// the statement did not exist. Used by the choke-point query to
// search for the minimum cover that breaks a grant.
func (m *CompiledModel) EvaluateAccessWith(suppressed map[int]bool) z3.Bool {
	allows := []z3.Bool{}
	denies := []z3.Bool{}
	for i := range m.Stmt {
		if suppressed[i] {
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
