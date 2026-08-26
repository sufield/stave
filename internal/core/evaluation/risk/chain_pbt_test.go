package risk

import (
	"fmt"
	"slices"
	"testing"

	"pgregory.net/rapid"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestPBT_ChainThreshold_Correct(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		numLegs := rapid.IntRange(2, 6).Draw(t, "numLegs")
		threshold := rapid.IntRange(1, numLegs).Draw(t, "threshold")

		legs := make([]kernel.ControlID, numLegs)
		for i := range legs {
			legs[i] = kernel.ControlID(fmt.Sprintf("CTL.PBT.%03d", i))
		}

		chain := policy.ChainDefinition{
			ID:                  "pbt_chain",
			Description:         "PBT generated chain",
			ControlIDs:          legs,
			EscalationThreshold: threshold,
			CompoundSeverity:    policy.SeverityHigh,
		}

		lookup := make(map[kernel.ControlID]*policy.ControlDefinition, numLegs)
		for _, id := range legs {
			lookup[id] = &policy.ControlDefinition{
				Params: policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
			}
		}

		numFiring := rapid.IntRange(0, numLegs).Draw(t, "numFiring")

		// Pick which legs fire via a shuffled prefix.
		indices := make([]int, numLegs)
		for i := range indices {
			indices[i] = i
		}
		perm := rapid.Permutation(indices).Draw(t, "perm")
		firingSet := make(map[kernel.ControlID]bool, numFiring)
		var failures []FailingControl
		for i := range numFiring {
			id := legs[perm[i]]
			firingSet[id] = true
			failures = append(failures, FailingControl{
				ControlID: id,
				AssetID:   "asset-pbt",
			})
		}

		findings := DetectChains(failures, []policy.ChainDefinition{chain}, lookup, nil)

		if numFiring >= threshold {
			if len(findings) != 1 {
				t.Fatalf("threshold=%d firing=%d: expected 1 finding, got %d",
					threshold, numFiring, len(findings))
			}
			f := findings[0]
			if f.ChainID != "pbt_chain" {
				t.Fatalf("ChainID = %q, want pbt_chain", f.ChainID)
			}
			// ControlsFailing must be exactly the firing set.
			if len(f.ControlsFailing) != numFiring {
				t.Fatalf("ControlsFailing count = %d, want %d", len(f.ControlsFailing), numFiring)
			}
			for _, cid := range f.ControlsFailing {
				if !firingSet[cid] {
					t.Errorf("ControlsFailing contains %s which did not fire", cid)
				}
			}
			// MissingSafeguards must be exactly the non-firing legs.
			expectedHolding := numLegs - numFiring
			if len(f.MissingSafeguards) != expectedHolding {
				t.Fatalf("MissingSafeguards count = %d, want %d", len(f.MissingSafeguards), expectedHolding)
			}
			for _, cid := range f.MissingSafeguards {
				if firingSet[cid] {
					t.Errorf("MissingSafeguards contains %s which DID fire", cid)
				}
			}
		} else {
			if len(findings) != 0 {
				t.Fatalf("threshold=%d firing=%d: expected 0 findings, got %d",
					threshold, numFiring, len(findings))
			}
		}
	})
}

func TestPBT_ChainThreshold_EmptyFailures(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		numLegs := rapid.IntRange(2, 6).Draw(t, "numLegs")
		threshold := rapid.IntRange(1, numLegs).Draw(t, "threshold")

		legs := make([]kernel.ControlID, numLegs)
		for i := range legs {
			legs[i] = kernel.ControlID(fmt.Sprintf("CTL.EMPTY.%03d", i))
		}

		chain := policy.ChainDefinition{
			ID:                  "empty_chain",
			ControlIDs:          legs,
			EscalationThreshold: threshold,
			CompoundSeverity:    policy.SeverityMedium,
		}

		findings := DetectChains(nil, []policy.ChainDefinition{chain}, nil, nil)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for empty failures, got %d", len(findings))
		}
	})
}

func TestPBT_ChainThreshold_CrossAssetIsolation(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		numLegs := rapid.IntRange(2, 4).Draw(t, "numLegs")

		legs := make([]kernel.ControlID, numLegs)
		for i := range legs {
			legs[i] = kernel.ControlID(fmt.Sprintf("CTL.CROSS.%03d", i))
		}

		chain := policy.ChainDefinition{
			ID:                  "cross_chain",
			ControlIDs:          legs,
			EscalationThreshold: numLegs, // all must fire
			CompoundSeverity:    policy.SeverityCritical,
		}

		lookup := make(map[kernel.ControlID]*policy.ControlDefinition, numLegs)
		for _, id := range legs {
			lookup[id] = &policy.ControlDefinition{
				Params: policy.NewParams(map[string]any{"attack_stage": "exfiltration"}),
			}
		}

		// Each leg fires on a DIFFERENT asset — should not trigger.
		var failures []FailingControl
		for i, id := range legs {
			failures = append(failures, FailingControl{
				ControlID: id,
				AssetID:   asset.ID(fmt.Sprintf("asset-%d", i)),
			})
		}

		findings := DetectChains(failures, []policy.ChainDefinition{chain}, lookup, nil)
		if len(findings) != 0 {
			t.Fatalf("cross-asset failures should not trigger asset-scoped chain, got %d findings", len(findings))
		}
	})
}

func TestPBT_ChainThreshold_SeverityPreserved(t *testing.T) {
	t.Parallel()

	severities := []policy.Severity{
		policy.SeverityLow,
		policy.SeverityMedium,
		policy.SeverityHigh,
		policy.SeverityCritical,
	}

	rapid.Check(t, func(t *rapid.T) {
		sev := rapid.SampledFrom(severities).Draw(t, "severity")

		chain := policy.ChainDefinition{
			ID:                  "sev_chain",
			ControlIDs:          []kernel.ControlID{"CTL.SEV.001", "CTL.SEV.002"},
			EscalationThreshold: 2,
			CompoundSeverity:    sev,
		}

		lookup := map[kernel.ControlID]*policy.ControlDefinition{
			"CTL.SEV.001": {Params: policy.NewParams(map[string]any{"attack_stage": "initial_access"})},
			"CTL.SEV.002": {Params: policy.NewParams(map[string]any{"attack_stage": "exfiltration"})},
		}

		failures := failingControls("asset-sev", "CTL.SEV.001", "CTL.SEV.002")
		findings := DetectChains(failures, []policy.ChainDefinition{chain}, lookup, nil)

		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Severity != sev {
			t.Errorf("Severity = %v, want %v", findings[0].Severity, sev)
		}
	})
}

func TestPBT_ChainThreshold_FindingsOrdered(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		numChains := rapid.IntRange(2, 5).Draw(t, "numChains")

		var chains []policy.ChainDefinition
		lookup := make(map[kernel.ControlID]*policy.ControlDefinition)
		var failures []FailingControl

		for i := range numChains {
			a := kernel.ControlID(fmt.Sprintf("CTL.ORD.%d.A", i))
			b := kernel.ControlID(fmt.Sprintf("CTL.ORD.%d.B", i))
			chains = append(chains, policy.ChainDefinition{
				ID:                  kernel.ChainID(fmt.Sprintf("ord_chain_%d", i)),
				ControlIDs:          []kernel.ControlID{a, b},
				EscalationThreshold: 2,
				CompoundSeverity:    policy.SeverityHigh,
			})
			lookup[a] = &policy.ControlDefinition{
				Params: policy.NewParams(map[string]any{"attack_stage": "initial_access"}),
			}
			lookup[b] = &policy.ControlDefinition{
				Params: policy.NewParams(map[string]any{"attack_stage": "exfiltration"}),
			}
			failures = append(failures,
				FailingControl{ControlID: a, AssetID: "asset-ord"},
				FailingControl{ControlID: b, AssetID: "asset-ord"},
			)
		}

		findings := DetectChains(failures, chains, lookup, nil)

		if len(findings) != numChains {
			t.Fatalf("expected %d findings, got %d", numChains, len(findings))
		}

		// Verify deterministic sort order (by ChainID, ScopeID, AssetID).
		sorted := slices.IsSortedFunc(findings, func(a, b findingsdata.CompoundFinding) int {
			if a.ChainID < b.ChainID {
				return -1
			}
			if a.ChainID > b.ChainID {
				return 1
			}
			return 0
		})
		if !sorted {
			t.Errorf("findings not sorted by ChainID")
		}
	})
}
