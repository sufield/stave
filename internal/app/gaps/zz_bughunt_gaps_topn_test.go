package gaps

import (
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

func TestBugHunt_Analyze_TopN_Capped(t *testing.T) {
	controls := []policy.ControlDefinition{
		{
			ID:                   "CTL.S3.PUBLIC.001",
			Severity:             policy.SeverityHigh,
			ApplicableAssetTypes: []kernel.AssetType{"aws_s3_bucket"},
			UnsafePredicate: policy.UnsafePredicate{
				All: []policy.PredicateRule{
					{Field: predicate.NewFieldPath("properties.storage.kind"), Op: predicate.OpEq},
				},
			},
		},
	}

	snapshots := []asset.Snapshot{
		{
			Assets: []asset.Asset{
				{
					ID:   "bucket1",
					Type: "aws_s3_bucket",
					Properties: map[string]any{
						"some_other_field": true,
					},
				},
			},
		},
	}

	// We only have 1 gap ("properties.storage.kind").
	// Request topN = 5 (which is > total gaps).
	report := Analyze(controls, nil, snapshots, 5)

	if len(report.Gaps) != 1 {
		t.Fatalf("expected 1 gap, got %d", len(report.Gaps))
	}

	if report.Summary.TopN != 1 {
		t.Errorf("expected Summary.TopN to be capped at 1, got %d", report.Summary.TopN)
	}
}
