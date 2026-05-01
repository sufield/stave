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
	// AWS implicit deny: if the bucket has no policy, or the policy
	// has zero statements, every API request is denied unless an
	// identity-based or session policy explicitly allows it. The
	// resource-based policy alone confers no access, so from the
	// policy-evaluator's perspective the report is ScoreSafe — the
	// absence of a policy does not by itself create exposure. The
	// "should this bucket have a policy at all?" question is a
	// posture concern handled by CTL.S3.POLICY.EXISTS.001, not here.
	// See: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
	if doc == nil || len(doc.statements) == 0 {
		return risk.Report{Score: risk.ScoreSafe}
	}

	report := risk.Report{}

	for i := range doc.statements {
		stmt := &doc.statements[i]
		if !stmt.GrantsAccess() {
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
