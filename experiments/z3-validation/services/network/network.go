// Package network holds the SG + NACL Z3 validation experiment —
// the fourth service in dependency order. Natural bitvector
// encoding (CIDR ranges, port ranges, protocol numbers) parallels
// the SecGuru ACL model.
//
// Stub implementation; RunZ3 returns nil. Full model in a
// follow-up commit.
package network

import (
	"context"

	"github.com/sufield/stave/experiments/z3-validation/harness"
)

type Experiment struct{}

func New() *Experiment { return &Experiment{} }

func (e *Experiment) Name() string { return "network" }

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
			"security_group_rules",
			"nacl_first_match_semantics",
			"vpc_peering",
			"cidr_ipv4_bitvector",
			"cidr_ipv6_bitvector",
			"port_range_bitvector",
			"protocol_number",
		},
		KnownLimitations: []string{
			"Network model is not yet implemented; this service emits no Z3 findings.",
		},
	}
}
