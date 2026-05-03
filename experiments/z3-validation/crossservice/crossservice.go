// Package crossservice runs queries that compose multiple
// per-service Z3 models. It is the sixth and final service in
// the experiment order — it runs only after each individual
// service has cleared the >95% agreement gate. Per the
// experiment plan, a wrong individual model produces a wrong
// composed query, and the operator cannot tell which model
// caused the failure if the individual gates haven't passed.
//
// This package is a stub. The Capital-One-shaped reachability
// query (Cognito → IAM → S3) and the IAM/S3/KMS compatibility
// query land after every individual service is green.
package crossservice

import (
	"context"

	"github.com/sufield/stave/experiments/z3-validation/harness"
)

// QueryName constants for the cross-service queries the harness
// will eventually emit. Listed here so the report shape is
// known up-front.
const (
	QueryUnauthToS3Data   = "unauth_to_s3_data"
	QueryIAMS3KMSCompat   = "iam_s3_kms_compat"
	QueryNetworkToService = "network_to_service"
)

// Experiment satisfies [harness.ServiceExperiment] for the
// cross-service slot. RunZ3 emits nothing today; the operator
// running `make experiment-cross` sees an empty agreement
// report with the not-yet-modeled note.
type Experiment struct{}

func New() *Experiment { return &Experiment{} }

func (e *Experiment) Name() string { return "crossservice" }

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
			QueryUnauthToS3Data,
			QueryIAMS3KMSCompat,
			QueryNetworkToService,
		},
		KnownLimitations: []string{
			"Cross-service composition runs only after every individual service clears the >95% agreement gate.",
		},
	}
}
