package policy

import (
	"slices"

	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// Evaluator translates AWS S3 bucket policy constructs into risk assessments.
// It bridges the vendor-specific policy model and the domain risk engine.
type Evaluator struct {
	// TrustedCIDRs allows the evaluator to ignore specific network ranges
	// when calculating exposure.
	TrustedCIDRs []string
	Resolver     risk.PermissionResolver
}

// NewEvaluator constructs a new policy evaluator.
func NewEvaluator(trusted []string, resolver risk.PermissionResolver) *Evaluator {
	return &Evaluator{TrustedCIDRs: slices.Clone(trusted), Resolver: resolver}
}

// Evaluate computes a risk report by analyzing each Allow statement.
// Deny statements are skipped — they reduce exposure and are handled
// by the AWS engine itself. An empty or missing Effect defaults to
// "not Allow" (safe) per AWS policy semantics.
func (e *Evaluator) Evaluate(doc *Document) risk.Report {
	if doc == nil || len(doc.statements) == 0 {
		return risk.Report{Score: risk.ScoreSafe}
	}

	report := risk.Report{}

	for _, stmt := range doc.statements {
		if !stmt.Effect.IsAllow() {
			continue
		}

		actions := risk.NormalizeActions([]string(stmt.Action))
		perms := risk.ResolveActions(actions, e.Resolver)
		report.Permissions |= perms

		scope := stmt.PrincipalScope()
		analysis := stmt.ConditionAnalysis()

		ctx := risk.StatementContext{
			Permissions:     perms,
			IsPublic:        scope.IsPublic(),
			IsAuthenticated: scope == kernel.ScopeAuthenticated,
			IsNetworkScoped: analysis.IsNetworkScoped(),
			IsAllow:         true,
		}
		report.UpdateReport(ctx.Evaluate())
	}

	return report
}
