package policy

import (
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
)

// Evaluator encapsulates policy scoring rules.
type Evaluator struct {
	TrustedCIDRs []string
	Resolver     risk.PermissionResolver
}

// NewEvaluator constructs a new policy evaluator.
func NewEvaluator(trusted []string, resolver risk.PermissionResolver) *Evaluator {
	return &Evaluator{TrustedCIDRs: trusted, Resolver: resolver}
}

// Evaluate computes a policy risk report from a pre-parsed Document.
// The Document must have been created via Parse() at the adapter boundary.
func (e *Evaluator) Evaluate(doc *Document) risk.Report {
	if doc == nil || len(doc.statements) == 0 {
		return risk.Report{Score: risk.ScoreSafe}
	}

	report := risk.Report{}

	for _, stmt := range doc.statements {
		if stmt.Effect != "" && !stmt.Effect.IsAllow() {
			continue
		}

		actions := risk.NormalizeActions([]string(stmt.Action))
		perms := risk.ResolveActions(actions, e.Resolver)
		report.Permissions |= perms

		isPublic, isAuth := classifyPolicyPrincipal(stmt.decodeRaw(stmt.Principal))
		cond := stmt.ConditionAnalysis()

		ctx := risk.StatementContext{
			Permissions:     perms,
			IsPublic:        isPublic,
			IsAuthenticated: isAuth,
			IsNetworkScoped: cond.IsNetworkScoped(),
			IsAllow:         stmt.Effect == "" || stmt.Effect.IsAllow(),
		}
		report.UpdateReport(ctx.Evaluate())
	}

	return report
}

func classifyPolicyPrincipal(principal any) (isPublic bool, isAuthenticated bool) {
	return IsPublicPrincipal(principal), isAuthenticatedPrincipal(principal)
}
