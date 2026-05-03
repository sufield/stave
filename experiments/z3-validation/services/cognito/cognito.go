// Package cognito holds the Cognito identity-pool Z3 validation
// experiment — the fifth service in dependency order. Depends on
// the IAM model from service 2: an identity-pool finding chains
// pool → unauth role → IAM evaluation.
//
// Stub implementation; RunZ3 returns nil. The real model lands
// after the gap-closure controls (CTL.COGNITO.IDPOOL.UNAUTH.*)
// are merged into the catalog.
package cognito

import (
	"context"

	"github.com/sufield/stave/experiments/z3-validation/harness"
)

type Experiment struct{}

func New() *Experiment { return &Experiment{} }

func (e *Experiment) Name() string { return "cognito" }

func (e *Experiment) ControlMapping() map[string]string {
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
			"identity_pool_unauth_role",
			"identity_pool_auth_role",
			"role_to_iam_chain",
			"role_to_resource_grant",
		},
		KnownLimitations: []string{
			"Cognito model is not yet implemented; this service emits no Z3 findings.",
			"Awaiting CTL.COGNITO.IDPOOL.* gap-closure controls.",
		},
	}
}
