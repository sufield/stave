package diff

import (
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// CompoundInput holds the chain engine output for one snapshot.
type CompoundInput struct {
	Findings []findings.CompoundFinding
	NearMiss []findings.NearMissChain
}

// ComputeCompoundImpact compares chain engine results from two snapshots
// and produces the compound-level risk delta.
func ComputeCompoundImpact(baseline, current CompoundInput) *RiskDelta {
	delta := &RiskDelta{}

	baseChains := indexChains(baseline.Findings)
	currChains := indexChains(current.Findings)

	// Chains activated: in current but not in baseline.
	for id, cf := range currChains {
		if _, was := baseChains[id]; !was {
			delta.ChainsActivated = append(delta.ChainsActivated, ChainActivation{
				ChainID:  string(id),
				Severity: cf.Severity.String(),
				Cause:    controlIDStrings(cf.ControlsFailing),
			})
		}
	}

	// Chains resolved: in baseline but not in current.
	for id, cf := range baseChains {
		if _, still := currChains[id]; !still {
			delta.ChainsResolved = append(delta.ChainsResolved, ChainResolution{
				ChainID: string(id),
				Cause:   controlIDStrings(cf.ControlsFailing),
			})
		}
	}

	// Distance changes: compare near-miss chains.
	baseNM := indexNearMiss(baseline.NearMiss)
	currNM := indexNearMiss(current.NearMiss)

	for id, currMiss := range currNM {
		if baseMiss, was := baseNM[id]; was {
			baseDist := len(baseMiss)
			currDist := len(currMiss)
			if baseDist != currDist {
				delta.DistanceChanges = append(delta.DistanceChanges, DistanceChange{
					ChainID:     string(id),
					WasDistance: baseDist,
					NowDistance: currDist,
				})
			}
		}
	}

	// New vs resolved near-miss (a near-miss appearing means a chain moved
	// from distance-N to distance-1).
	for id := range currNM {
		if _, was := baseNM[id]; !was {
			if _, active := currChains[id]; !active {
				delta.DistanceChanges = append(delta.DistanceChanges, DistanceChange{
					ChainID:     string(id),
					WasDistance: -1, // was not near-miss
					NowDistance: 1,
				})
			}
		}
	}

	// Finding counts.
	delta.NewFindings = max(len(current.Findings)-len(baseline.Findings), 0)
	delta.ResolvedFindings = max(len(baseline.Findings)-len(current.Findings), 0)

	return delta
}

func indexChains(fs []findings.CompoundFinding) map[kernel.ChainID]*findings.CompoundFinding {
	idx := make(map[kernel.ChainID]*findings.CompoundFinding, len(fs))
	for i := range fs {
		idx[fs[i].ChainID] = &fs[i]
	}
	return idx
}

// indexNearMiss groups near-miss entries by chain, counting distinct missing
// controls (distance = number of controls away from activation).
func indexNearMiss(nms []findings.NearMissChain) map[kernel.ChainID][]kernel.ControlID {
	idx := make(map[kernel.ChainID][]kernel.ControlID)
	for _, nm := range nms {
		idx[nm.ChainID] = append(idx[nm.ChainID], nm.MissingControl)
	}
	return idx
}

func controlIDStrings(ids []kernel.ControlID) []string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = string(id)
	}
	return s
}
