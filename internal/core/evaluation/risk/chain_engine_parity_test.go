package risk

import (
	"cmp"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	findingsdata "github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

// detectChainsLegacy is a verbatim copy of the pre-inverted-index
// implementation of DetectChains. It exists only as a regression
// oracle for the new index-driven shape — the parity test below
// runs both against the same inputs and asserts DeepEqual on the
// returned slices. When the legacy form drifts from the new one,
// the test fails with the input that produced the divergence.
//
// Deliberately not exported and not reachable from non-test code.
// Delete this file only when the index-driven path has lived in
// production long enough that the parity net is no longer
// foundational.
func detectChainsLegacy(
	failures []FailingControl,
	chains []policy.ChainDefinition,
	controlLookup map[kernel.ControlID]*policy.ControlDefinition,
	scopeResolver ScopeResolver,
) []findingsdata.CompoundFinding {
	var findings []findingsdata.CompoundFinding

	for i := range chains {
		chain := &chains[i]
		chainMembers := make(map[kernel.ControlID]struct{}, len(chain.ControlIDs))
		for _, cid := range chain.ControlIDs {
			chainMembers[cid] = struct{}{}
		}

		byScope := make(map[string]map[kernel.ControlID]struct{})
		assetsByScope := make(map[string]map[asset.ID]struct{})
		resolvedByScope := make(map[string]struct{})
		for j := range failures {
			f := &failures[j]
			if _, ok := chainMembers[f.ControlID]; !ok {
				continue
			}
			scope, resolved := groupingKey(chain, f.AssetID, scopeResolver)
			if byScope[scope] == nil {
				byScope[scope] = make(map[kernel.ControlID]struct{})
				assetsByScope[scope] = make(map[asset.ID]struct{})
			}
			byScope[scope][f.ControlID] = struct{}{}
			assetsByScope[scope][f.AssetID] = struct{}{}
			if resolved {
				resolvedByScope[scope] = struct{}{}
			}
		}

		for scope, scopeFailing := range byScope {
			var failing []kernel.ControlID
			var holding []kernel.ControlID
			for _, cid := range chain.ControlIDs {
				if _, ok := scopeFailing[cid]; ok {
					failing = append(failing, cid)
				} else {
					holding = append(holding, cid)
				}
			}

			if len(failing) < chain.EscalationThreshold {
				continue
			}

			stageSet := make(map[kernel.AttackStage]struct{})
			maxBlast := 1.0
			for _, cid := range failing {
				if ctl, ok := controlLookup[cid]; ok {
					if stage := ctl.AttackStage(); stage != "" {
						stageSet[stage] = struct{}{}
					}
					mult := scopeAdjustedBlast(ctl)
					if mult > maxBlast {
						maxBlast = mult
					}
				}
			}

			stages := make([]kernel.AttackStage, 0, len(stageSet))
			for s := range stageSet {
				stages = append(stages, s)
			}
			slices.SortFunc(stages, func(a, b kernel.AttackStage) int {
				return cmp.Compare(a, b)
			})

			escalation := ChainEscalation(len(failing))
			base := baseScoreFromMembers(failing, controlLookup)
			score := Compound(base, escalation, maxBlast)
			if score > float64(ScoreCatastrophic) {
				score = float64(ScoreCatastrophic)
			}

			narrative := buildNarrative(chain, failing)
			contributing := sortedAssetIDs(assetsByScope[scope])
			finding := findingsdata.CompoundFinding{
				ChainID:           chain.ID,
				AssetID:           contributing[0],
				Description:       chain.Description,
				ControlsFailing:   failing,
				MissingSafeguards: holding,
				CompoundScore:     score,
				Severity:          chain.CompoundSeverity,
				Narrative:         narrative,
				AttackStages:      stages,
			}
			_, isResolved := resolvedByScope[scope]
			if chain.ScopeField != "" && isResolved {
				finding.ScopeID = scope
				finding.ScopeField = chain.ScopeField
				finding.ContributingAssets = contributing
			}
			findings = append(findings, finding)
		}
	}

	slices.SortFunc(findings, func(a, b findingsdata.CompoundFinding) int {
		if c := cmp.Compare(a.ChainID, b.ChainID); c != 0 {
			return c
		}
		if c := cmp.Compare(a.ScopeID, b.ScopeID); c != 0 {
			return c
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})

	return findings
}

// makeSyntheticCatalog builds a chains catalog and matching
// control-lookup of the requested size. Each chain has a fixed
// fan-out (4 controls), threshold 2, and a couple of chains share
// controls so the inverted index actually has non-trivial slices.
// Returned shapes are stable across calls (deterministic IDs) so
// the parity test can compare results without fixture-file churn.
func makeSyntheticCatalog(numChains, numControls int) (
	[]policy.ChainDefinition,
	map[kernel.ControlID]*policy.ControlDefinition,
) {
	const fanOut = 4
	controls := make(map[kernel.ControlID]*policy.ControlDefinition, numControls)
	for i := range numControls {
		id := kernel.ControlID(fmt.Sprintf("CTL.%05d", i))
		controls[id] = &policy.ControlDefinition{
			ID:       id,
			Severity: policy.SeverityHigh,
		}
	}

	chains := make([]policy.ChainDefinition, 0, numChains)
	for i := range numChains {
		ids := make([]kernel.ControlID, 0, fanOut)
		for j := range fanOut {
			// Stride by i+j so most chains share at least one
			// control with another — exercises the multi-index
			// branch of the inverted index.
			idx := (i*fanOut + j) % numControls
			ids = append(ids, kernel.ControlID(fmt.Sprintf("CTL.%05d", idx)))
		}
		chains = append(chains, policy.ChainDefinition{
			ID:                  kernel.ChainID(fmt.Sprintf("CHAIN.%05d", i)),
			Description:         fmt.Sprintf("synthetic chain %d", i),
			ControlIDs:          ids,
			EscalationThreshold: 2,
			CompoundSeverity:    policy.SeverityHigh,
		})
	}
	return chains, controls
}

// makeSyntheticFailures builds a (mostly-failing) failure slice
// against the catalog. The asset-id rotation lets a small number
// of chains land multi-asset findings.
func makeSyntheticFailures(numControls, numFailures int) []FailingControl {
	out := make([]FailingControl, 0, numFailures)
	for i := range numFailures {
		out = append(out, FailingControl{
			ControlID: kernel.ControlID(fmt.Sprintf("CTL.%05d", i%numControls)),
			AssetID:   asset.ID(fmt.Sprintf("asset-%d", i%50)),
		})
	}
	return out
}

func TestDetectChains_ParityWithLegacy(t *testing.T) {
	cases := []struct {
		name        string
		numChains   int
		numControls int
		numFailures int
	}{
		{"empty failures", 50, 100, 0},
		{"single failure", 50, 100, 1},
		{"all controls failing", 100, 50, 50},
		{"production scale 597 chains", 597, 1000, 5000},
		{"projected scale 2000 chains", 2000, 1000, 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chains, controls := makeSyntheticCatalog(tc.numChains, tc.numControls)
			failures := makeSyntheticFailures(tc.numControls, tc.numFailures)

			got := DetectChains(failures, chains, controls, nil)
			want := detectChainsLegacy(failures, chains, controls, nil)

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("parity drift\n  got:  %d findings\n  want: %d findings\n  first divergence at %s",
					len(got), len(want), firstDiff(got, want))
			}
		})
	}
}

func TestDetectChains_ParityWithScopeResolver(t *testing.T) {
	// Build a 50-chain catalog where every other chain has a
	// ScopeField. The resolver returns a deterministic value
	// based on asset.ID so the parity test exercises the scope
	// grouping branch — the one that adds ContributingAssets /
	// ScopeID / ScopeField to the output.
	chains, controls := makeSyntheticCatalog(50, 100)
	for i := range chains {
		if i%2 == 0 {
			chains[i].ScopeField = "user_pool_id"
		}
	}
	failures := makeSyntheticFailures(100, 200)
	resolver := func(id asset.ID, path string) (string, bool) {
		if path != "user_pool_id" {
			return "", false
		}
		return "pool-" + string(id), true
	}

	got := DetectChains(failures, chains, controls, resolver)
	want := detectChainsLegacy(failures, chains, controls, resolver)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parity drift with scope resolver: got %d findings, want %d (first diff: %s)",
			len(got), len(want), firstDiff(got, want))
	}
}

func TestDetectChains_NilResolverFallsBackToAssetID(t *testing.T) {
	// Resolver=nil branch is part of the documented contract;
	// behaviour must match the legacy form even when ScopeField
	// is set on every chain.
	chains, controls := makeSyntheticCatalog(20, 50)
	for i := range chains {
		chains[i].ScopeField = "anything"
	}
	failures := makeSyntheticFailures(50, 80)

	got := DetectChains(failures, chains, controls, nil)
	want := detectChainsLegacy(failures, chains, controls, nil)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nil-resolver parity drift")
	}
}

func firstDiff(a, b []findingsdata.CompoundFinding) string {
	n := min(len(b), len(a))
	for i := range n {
		if !reflect.DeepEqual(a[i], b[i]) {
			return fmt.Sprintf("index %d: %+v vs %+v", i, a[i], b[i])
		}
	}
	return fmt.Sprintf("length difference: got %d, want %d", len(a), len(b))
}
