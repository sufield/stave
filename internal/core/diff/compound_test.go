package diff

import (
	"testing"

	"github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestComputeCompoundImpact_ChainActivated(t *testing.T) {
	baseline := CompoundInput{}
	current := CompoundInput{
		Findings: []findings.CompoundFinding{
			{ChainID: "capital_one_path", Severity: controldef.SeverityCritical},
		},
	}

	delta := ComputeCompoundImpact(baseline, current)

	if len(delta.ChainsActivated) != 1 {
		t.Fatalf("want 1 activated chain, got %d", len(delta.ChainsActivated))
	}
	if delta.ChainsActivated[0].ChainID != "capital_one_path" {
		t.Errorf("want capital_one_path, got %s", delta.ChainsActivated[0].ChainID)
	}
	if delta.ChainsActivated[0].Severity != "critical" {
		t.Errorf("want critical, got %s", delta.ChainsActivated[0].Severity)
	}
}

func TestComputeCompoundImpact_ChainResolved(t *testing.T) {
	baseline := CompoundInput{
		Findings: []findings.CompoundFinding{
			{
				ChainID:         "abandoned_instance_path",
				ControlsFailing: []kernel.ControlID{"CTL.EC2.001", "CTL.EC2.002"},
			},
		},
	}
	current := CompoundInput{}

	delta := ComputeCompoundImpact(baseline, current)

	if len(delta.ChainsResolved) != 1 {
		t.Fatalf("want 1 resolved chain, got %d", len(delta.ChainsResolved))
	}
	if delta.ChainsResolved[0].ChainID != "abandoned_instance_path" {
		t.Errorf("want abandoned_instance_path, got %s", delta.ChainsResolved[0].ChainID)
	}
}

func TestComputeCompoundImpact_DistanceChange(t *testing.T) {
	baseline := CompoundInput{
		NearMiss: []findings.NearMissChain{
			{ChainID: "cicd_path", MissingControl: "CTL.OIDC.001"},
			{ChainID: "cicd_path", MissingControl: "CTL.OIDC.002"},
		},
	}
	current := CompoundInput{
		NearMiss: []findings.NearMissChain{
			{ChainID: "cicd_path", MissingControl: "CTL.OIDC.001"},
		},
	}

	delta := ComputeCompoundImpact(baseline, current)

	if len(delta.DistanceChanges) != 1 {
		t.Fatalf("want 1 distance change, got %d", len(delta.DistanceChanges))
	}
	dc := delta.DistanceChanges[0]
	if dc.ChainID != "cicd_path" {
		t.Errorf("want cicd_path, got %s", dc.ChainID)
	}
	if dc.WasDistance != 2 || dc.NowDistance != 1 {
		t.Errorf("want distance 2→1, got %d→%d", dc.WasDistance, dc.NowDistance)
	}
}

func TestComputeCompoundImpact_IdenticalSnapshots(t *testing.T) {
	same := CompoundInput{
		Findings: []findings.CompoundFinding{
			{ChainID: "existing_chain"},
		},
	}

	delta := ComputeCompoundImpact(same, same)

	if len(delta.ChainsActivated) != 0 {
		t.Errorf("want 0 activated, got %d", len(delta.ChainsActivated))
	}
	if len(delta.ChainsResolved) != 0 {
		t.Errorf("want 0 resolved, got %d", len(delta.ChainsResolved))
	}
}

func TestComputeCompoundImpact_NetDirection(t *testing.T) {
	delta := &RiskDelta{
		ChainsActivated: []ChainActivation{{ChainID: "a"}, {ChainID: "b"}},
		ChainsResolved:  []ChainResolution{{ChainID: "c"}},
	}
	if got := delta.NetDirection(); got != RiskIncreasing {
		t.Errorf("want RiskIncreasing, got %v", got)
	}

	delta2 := &RiskDelta{
		ChainsResolved: []ChainResolution{{ChainID: "a"}},
	}
	if got := delta2.NetDirection(); got != RiskDecreasing {
		t.Errorf("want RiskDecreasing, got %v", got)
	}
}
