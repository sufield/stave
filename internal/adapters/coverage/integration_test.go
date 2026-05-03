package coverage

import (
	"testing"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	corecov "github.com/sufield/stave/internal/core/evaluation/coverage"
)

// TestEndToEnd_RealCatalog confirms that the embedded inventory + the
// embedded control catalog produce the coverage counts cited in the
// methodology-coverage docs (17/21 for prowler/s3, 33/47 for prowler/iam).
// If this drifts, either the docs are stale or new controls/checks were
// added without updating one side.
func TestEndToEnd_RealCatalog(t *testing.T) {
	inventories, err := LoadEmbedded()
	if err != nil {
		t.Fatalf("LoadEmbedded: %v", err)
	}
	store := ctlbuiltin.NewControlStore(ctlbuiltin.EmbeddedFS(), "embedded", ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()))
	controls, err := store.All()
	if err != nil {
		t.Fatalf("load builtin controls: %v", err)
	}

	idx := corecov.BuildCoverageIndex(controls, inventories)

	cases := []struct {
		tool, domain string
		wantCovered  int
		wantTotal    int
	}{
		{"prowler", "s3", 20, 21},  // 17 covered + 3 partial = 20 distinct check_ids
		{"prowler", "iam", 44, 47}, // 39 covered + 5 partial = 44 distinct check_ids
	}
	for _, tc := range cases {
		dc := idx.ByTool[tc.tool][tc.domain]
		if dc.Covered != tc.wantCovered {
			t.Errorf("%s/%s Covered = %d, want %d", tc.tool, tc.domain, dc.Covered, tc.wantCovered)
		}
		if dc.Total != tc.wantTotal {
			t.Errorf("%s/%s Total = %d, want %d", tc.tool, tc.domain, dc.Total, tc.wantTotal)
		}
		if dc.Total-dc.Covered != len(dc.NotCoveredChecks) {
			t.Errorf("%s/%s NotCoveredChecks count = %d, want %d", tc.tool, tc.domain, len(dc.NotCoveredChecks), dc.Total-dc.Covered)
		}
	}
}
