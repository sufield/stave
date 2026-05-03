// Package iam holds the IAM Z3 validation experiment. It is the
// second service in dependency order — it is required for the
// cross-service queries that compose Cognito → IAM → S3
// reachability — and the most complex to model because of the
// AWS evaluation order (explicit-deny → SCP → resource-based
// → permissions-boundary → session → identity-based →
// implicit-deny).
//
// This package is a stub that satisfies [harness.ServiceExperiment]
// so the harness compiles. The model and compiler land in a
// follow-up commit; until then RunZ3 returns nil and the harness
// reports zero comparisons for IAM.
package iam

import (
	"context"

	"github.com/sufield/stave/experiments/z3-validation/harness"
)

type Experiment struct{}

func New() *Experiment { return &Experiment{} }

func (e *Experiment) Name() string { return "iam" }

func (e *Experiment) ControlMapping() map[string]string {
	// TODO: populate from `stave controls list --service iam` once
	// the IAM model lands. The catalog's overprivileged-role,
	// PassRole, and admin-reachability families collapse onto
	// "effective_permissions" / "privilege_escalation" /
	// "admin_reachability" Z3 queries per the experiment plan.
	return map[string]string{}
}

func (e *Experiment) RunZ3(ctx context.Context, fixtureDir string) ([]harness.Z3Finding, error) {
	return nil, nil
}

func (e *Experiment) CollapseRatio() (celControls, z3Queries int) {
	return 0, 0
}

func (e *Experiment) ModelCoverage() harness.ModelCoverage {
	return harness.ModelCoverage{
		NotModeled: []string{
			"identity_policy_evaluation",
			"resource_based_policy_evaluation",
			"permissions_boundary",
			"scp",
			"session_policy",
			"trust_policy_assume_role",
			"action_wildcard_expansion",
			"resource_arn_pattern_matching",
			"condition_keys",
		},
		KnownLimitations: []string{
			"IAM model is not yet implemented; this service emits no Z3 findings.",
		},
	}
}
