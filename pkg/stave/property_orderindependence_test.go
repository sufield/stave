package stave_test

import (
	"fmt"
	"reflect"
	"testing"

	"pgregory.net/rapid"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/pkg/stave"
)

// findingKey is the order-independent identity of a finding: the (control,
// asset, severity) triple. One finding exists per (control, asset), so this key
// gives the finding SET its identity independent of slice order.
func findingKey(f stave.Finding) string {
	return fmt.Sprintf("%s|%s|%s", f.ControlID, f.AssetID, f.Severity)
}

// findingMultiset reduces a finding slice to a key->count map, discarding order.
// Counts (not just presence) so a dropped or duplicated finding is still caught.
func findingMultiset(findings []stave.Finding) map[string]int {
	m := make(map[string]int, len(findings))
	for _, f := range findings {
		m[findingKey(f)]++
	}
	return m
}

// shuffleAssetsWithin returns a copy of snaps with each snapshot's assets
// reordered by a rapid-drawn permutation (Fisher-Yates). rapid shrinks toward
// the identity permutation, so a counterexample reduces to the smallest
// reordering that changes the result.
func shuffleAssetsWithin(rt *rapid.T, snaps []asset.Snapshot) []asset.Snapshot {
	out := make([]asset.Snapshot, len(snaps))
	for i, s := range snaps {
		assets := make([]asset.Asset, len(s.Assets))
		copy(assets, s.Assets)
		for k := len(assets) - 1; k > 0; k-- {
			j := rapid.IntRange(0, k).Draw(rt, "swap")
			assets[k], assets[j] = assets[j], assets[k]
		}
		s.Assets = assets
		out[i] = s
	}
	return out
}

// TestProperty_FindingsAreOrderIndependent asserts that the SET of findings is
// invariant under reordering the resources within each snapshot.
//
// Why a violation matters: the input order of resources is an accident of the
// upstream collector (Steampipe row order, map iteration, pagination), never a
// security signal. Compound-risk detection joins resources across a snapshot,
// which is exactly the kind of logic that can silently become order-dependent
// under an optimization (early-exit, first-match dedup, a bounded worklist).
// If shuffling the assets changes which findings are produced, the verdict
// depends on collector happenstance rather than the configuration itself.
func TestProperty_FindingsAreOrderIndependent(t *testing.T) {
	if testing.Short() {
		t.Skip("property test: drives the full Apply pipeline over many generated inputs; skipped under -short")
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	rapid.Check(t, func(rt *rapid.T) {
		snaps := genSnapshots(rt)
		cfg1, cleanup1 := writePropFixture(t, snaps)
		defer cleanup1()
		base := findingMultiset(applyOrFatal(rt, cfg1).Findings)

		shuffled := shuffleAssetsWithin(rt, snaps)
		cfg2, cleanup2 := writePropFixture(t, shuffled)
		defer cleanup2()
		got := findingMultiset(applyOrFatal(rt, cfg2).Findings)

		if !reflect.DeepEqual(base, got) {
			rt.Fatalf("finding SET changed when assets were reordered within snapshots:\n"+
				"original order: %v\nshuffled order: %v", base, got)
		}
	})
}
