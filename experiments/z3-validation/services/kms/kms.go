// Package kms holds the KMS Z3 validation experiment — the third
// service in dependency order. Validates the cross-service
// pattern (IAM + KMS) before the network and Cognito models land.
//
// Stub implementation; RunZ3 returns nil. Full model in a
// follow-up commit.
package kms

import (
	"context"

	"github.com/sufield/stave/experiments/z3-validation/harness"
)

type Experiment struct{}

func New() *Experiment { return &Experiment{} }

func (e *Experiment) Name() string { return "kms" }

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
			"key_policy_evaluation",
			"kms_grant",
			"via_service_condition",
		},
		KnownLimitations: []string{
			"KMS model is not yet implemented; this service emits no Z3 findings.",
		},
	}
}
