package remediationimpact

import (
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_Analyze_ChainAssetScope(t *testing.T) {
	// Before has CHAIN.1 on asset-a.
	// After has CHAIN.1 on asset-b.
	// We expect:
	// - 1 deactivated chain (CHAIN.1 on asset-a is resolved).
	// Under the buggy code: it only indexes by ChainID, so it sees CHAIN.1 existed before and still exists (on asset-b),
	// and deletes it, reporting 0 deactivated chains!

	before := &report.Assessment{
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:  "CHAIN.1",
				AssetID:  "asset-a",
				Severity: policy.SeverityHigh,
			},
		},
	}

	after := &report.Assessment{
		ChainFindings: []findings.CompoundFinding{
			{
				ChainID:  "CHAIN.1",
				AssetID:  "asset-b",
				Severity: policy.SeverityHigh,
			},
		},
	}

	res, err := Analyze(Input{
		Before: before,
		After:  after,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(res.ChainsDeactivated) != 1 {
		t.Errorf("expected 1 deactivated chain (asset-a resolved), got %d", len(res.ChainsDeactivated))
	}
}
