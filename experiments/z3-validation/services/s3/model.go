package s3

import (
	"github.com/sufield/stave/experiments/z3-validation/harness"
)

// Experiment is the S3 [harness.ServiceExperiment] implementation.
// It is stateless — every RunZ3 call builds a fresh Z3 context
// and tears it down so two parallel runs cannot share state.
type Experiment struct{}

// New returns a freshly-constructed S3 experiment.
func New() *Experiment {
	return &Experiment{}
}

// Name returns "s3".
func (e *Experiment) Name() string { return "s3" }

// ModelCoverage names what the S3 model includes and what it
// deliberately omits. Today's coverage covers bucket-policy
// principals/actions/resources/conditions, public-access-block
// state, and the cross-account principal heuristic. Object-level
// ACLs, multi-region access points, and access-point policies
// are not modeled — fixtures that rely on those will appear in
// the cel_only.json subset and need a model extension before
// they migrate.
func (e *Experiment) ModelCoverage() harness.ModelCoverage {
	return harness.ModelCoverage{
		Modeled: []string{
			"bucket_policy_principals_actions_resources",
			"bucket_policy_conditions_org_id_source_vpc",
			"public_access_block",
			"cross_account_principal",
		},
		NotModeled: []string{
			"object_level_acl",
			"access_point_policy",
			"multi_region_access_point",
			"vpc_endpoint_policy",
			"scp_or_permissions_boundary",
		},
		KnownLimitations: []string{
			"Object-level ACL grants surface as CEL_ONLY when a fixture relies on them.",
			"Access-point policies override bucket policy at the AWS layer; the model evaluates the bucket policy in isolation.",
		},
	}
}
